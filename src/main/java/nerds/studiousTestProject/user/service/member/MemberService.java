package nerds.studiousTestProject.user.service.member;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nerds.studiousTestProject.user.dto.general.MemberLoginRequest;
import nerds.studiousTestProject.user.dto.general.MemberSignUpRequest;
import nerds.studiousTestProject.user.dto.general.MemberSignUpResponse;
import nerds.studiousTestProject.user.dto.general.token.JwtTokenResponse;
import nerds.studiousTestProject.user.entity.Member;
import nerds.studiousTestProject.user.entity.token.LogoutAccessToken;
import nerds.studiousTestProject.user.entity.token.RefreshToken;
import nerds.studiousTestProject.user.exception.message.ExceptionMessage;
import nerds.studiousTestProject.user.exception.model.TokenCheckFailException;
import nerds.studiousTestProject.user.exception.model.UserAuthException;
import nerds.studiousTestProject.user.repository.member.MemberRepository;
import nerds.studiousTestProject.user.service.token.LogoutAccessTokenService;
import nerds.studiousTestProject.user.service.token.RefreshTokenService;
import nerds.studiousTestProject.user.util.JwtTokenProvider;
import nerds.studiousTestProject.user.util.JwtTokenUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;
    private final RefreshTokenService refreshTokenService;
    private final LogoutAccessTokenService logoutAccessTokenService;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public MemberSignUpResponse register(MemberSignUpRequest signUpRequest) {
        String email = signUpRequest.getEmail();
        if (memberRepository.existsByEmail(email)) {
            throw new UserAuthException(ExceptionMessage.ALREADY_EXIST_USER);
        }

        String encode = passwordEncoder.encode(signUpRequest.getPassword());
        List<String> roles = signUpRequest.getRoles();
        Member member = Member.builder()
                .email(email)
                .password(encode)
                .roles(roles)
                .build();
        memberRepository.save(member);

        return member.toSignUpResponse();
    }

    // 로그인을 하는 시점에 토큰이 생성된다
    @Transactional
    public JwtTokenResponse login(MemberLoginRequest loginRequest) {
        String email = loginRequest.getEmail();
        String password = loginRequest.getPassword();

        Member member = authenticate(email, password);

        // 1. 토큰 생성
        String accessToken = jwtTokenProvider.createAccessToken(email, password);
        RefreshToken refreshToken = refreshTokenService.saveRefreshToken(member.getEmail());

        // 2. 쿠키에 Refresh 토큰 등록
        jwtTokenProvider.setRefreshTokenAtCookie(refreshToken);

        // 3. 생성한 토큰을 DTO에 담아 반환
        return JwtTokenResponse.from(accessToken);
    }

    public void logout(String accessToken) {
        String resolvedAccessToken = jwtTokenProvider.resolveToken(accessToken);
        if (resolvedAccessToken == null) {
            log.info("accessToken = {}", accessToken);
            throw new RuntimeException("토큰 해결 중 오류 발생");
        }

        String email = jwtTokenProvider.parseToken(resolvedAccessToken);

        Long remainTime = jwtTokenProvider.getRemainTime(resolvedAccessToken);
        refreshTokenService.deleteRefreshTokenByEmail(email);

        logoutAccessTokenService.saveLogoutAccessToken(LogoutAccessToken.from(email, resolvedAccessToken, remainTime));
    }

    /**
     * 사용자가 만료된 accessToken 과 만료되지 않은 refreshToken을 넘길 때 새로운 accessToken을 만들어 주는 메소드
     * @param refreshToken 사용자로부터 넘겨 받은 refreshToken
     * @return 새로운 accessToken 이 담긴 JwtTokenResponse 객체
     */
    public JwtTokenResponse reissue(String refreshToken) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getName() == null) {
            log.info("auth = {}", authentication);
            throw new UserAuthException(ExceptionMessage.NOT_AUTHORIZE_ACCESS);
        }

        String currentEmail = authentication.getName();
        RefreshToken redisRefreshToken = refreshTokenService.findRefreshTokenByEmail(currentEmail);

        if (redisRefreshToken == null || !refreshToken.equals(redisRefreshToken.getRefreshToken())) {
            log.info("refreshToken = {}", refreshToken);
            log.info("redisRefreshToken = {}", redisRefreshToken != null ? redisRefreshToken.getRefreshToken() : null);
            throw new TokenCheckFailException(ExceptionMessage.MISMATCH_TOKEN);
        }

//        Authorization 사용하여 패스워드 가져올 때 PROTECTED 되있으므로 DB에서 사용자 내역을 가져온다.
//        String password = userDetails.getPassword();
//        참고 : https://djunnni.gitbook.io/springboot/2019-11-30
//        Member member = memberRepository.findByEmail(currentEmail).get();
//        String password = passwordEncoder.encode(member.getPassword());

        return reissueTokens(refreshToken, authentication);
    }

    /**
     * 이메일, 비밀번호를 검증 후 일치하는 회원 정보 Entity 반환
     * @param email 사용자가 입력한 이메일
     * @param password 사용자가 입력한 비밀번호
     * @return 알맞는 회원 정보
     */
    private Member authenticate(String email, String password) {
        if (!memberRepository.existsByEmail(email)) {
            throw new UserAuthException(ExceptionMessage.USER_NOT_FOUND);
        }

        Member member = memberRepository.findByEmail(email).get();
        if (!passwordEncoder.matches(password, member.getPassword())) {
            throw new UserAuthException(ExceptionMessage.MISMATCH_PASSWORD);
        }

        return member;
    }

    private JwtTokenResponse reissueTokens(String refreshToken, Authentication authentication) {
        String accessToken = jwtTokenProvider.createAccessToken(authentication);
        if (!lessThanReissueExpirationTimesLeft(refreshToken)) {
            String email = authentication.getName();
            RefreshToken newRedisToken = refreshTokenService.saveRefreshToken(email);
            jwtTokenProvider.setRefreshTokenAtCookie(newRedisToken);
        }

        return JwtTokenResponse.from(accessToken);
    }

    private boolean lessThanReissueExpirationTimesLeft(String refreshToken) {
        return jwtTokenProvider.getRemainTime(refreshToken) < JwtTokenUtil.REISSUE_EXPIRE_TIME;
    }
}
