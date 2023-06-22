package nerds.studiousTestProject.user.service.member;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

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

    /**
     * 사용자가 입력한 정보를 가지고 MemberRepository에 저장하는 메소드
     * @param email 사용자 이메일
     * @param password 사용자 비밀번호
     * @param roles 사용자 권한 (이는 추후 회원가입 페이지로 구분할 예정, 일단은 값으로 넣어주자)
     * @param providerId 소셜 로그인인 경우 소셜 서버 유저의 고유 id, 일반 회원가입인 경우는 null
     */
    @Transactional
    public void register(String email, String password, List<String> roles, Long providerId) {
        if ((providerId != null && memberRepository.existsByProviderId(providerId)) || memberRepository.existsByEmail(email)) {
            throw new UserAuthException(ExceptionMessage.ALREADY_EXIST_USER);
        }

        String encode = passwordEncoder.encode(password);
        Member member = Member.builder()
                .email(email)
                .password(encode)
                .providerId(providerId)
                .roles(roles)
                .build();
        memberRepository.save(member);
    }

    /**
     * 로그인 하는 시점에 토큰을 생성해서 반환하는 메소드 (로그인을 하는 시점에 토큰이 생성된다)
     * @param email 사용자 이메일
     * @param password 사용자 비밀번호
     * @return 발급한 토큰 정보
     */
    @Transactional
    public JwtTokenResponse login(String email, String password) {
        Member member = authenticate(email, password);

        // 1. 토큰 생성
        String accessToken = jwtTokenProvider.createAccessToken(email, password);
        RefreshToken refreshToken = refreshTokenService.save(member.getEmail(), jwtTokenProvider.createRefreshToken());

        // 2. 쿠키에 Refresh 토큰 등록
        jwtTokenProvider.setRefreshTokenAtCookie(refreshToken);

        // 3. 생성한 토큰을 DTO에 담아 반환
        return JwtTokenResponse.from(accessToken);
    }

    /**
     * 현재 사용자의 토큰을 만료시고 블랙리스트에 저장하는 메소드
     * @param accessToken 사용자의 accessToken
     * @return 현재 사용자의 이메일
     */
    public String logout(String accessToken) {
        String resolvedAccessToken = jwtTokenProvider.resolveToken(accessToken);
        if (resolvedAccessToken == null) {
            log.info("accessToken = {}", accessToken);
            throw new RuntimeException("토큰 해결 중 오류 발생");
        }

        String email = jwtTokenProvider.parseToken(resolvedAccessToken);
        log.info("email = {}", email);

        Long remainTime = jwtTokenProvider.getRemainTime(resolvedAccessToken);
        refreshTokenService.deleteByEmail(email);

        logoutAccessTokenService.saveLogoutAccessToken(LogoutAccessToken.from(email, resolvedAccessToken, remainTime));

        return email;
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
        log.info("currentEmail = {}", currentEmail);
        RefreshToken redisRefreshToken = refreshTokenService.findByEmail(currentEmail);

        if (redisRefreshToken == null || !refreshToken.equals(redisRefreshToken.getRefreshToken())) {
            log.info("refreshToken = {}", refreshToken);
            log.info("redisRefreshToken = {}", redisRefreshToken != null ? redisRefreshToken.getRefreshToken() : "null");
            throw new TokenCheckFailException(ExceptionMessage.MISMATCH_TOKEN);
        }

//        Authorization 사용하여 패스워드 가져올 때 PROTECTED 되있으므로 DB에서 사용자 내역을 가져온다.
//        String password = userDetails.getPassword();
//        참고 : https://djunnni.gitbook.io/springboot/2019-11-30
//        Member member = memberRepository.findByEmail(currentEmail).get();
//        String password = passwordEncoder.encode(member.getPassword());

        return reissueToken(refreshToken, authentication);
    }

    /**
     * OAuth2Service 에서 사용
     * MemberRepository에서 email 값을 통해 providerId 찾아 반환하는 메소드
     * @param email 회원 이메일
     * @return 해당 email을 가진 Member의 providerId
     */
    public Long findProviderIdByEmail(String email) {
        Optional<Member> memberOptional = memberRepository.findByEmail(email);
        return memberOptional.orElseThrow(
                () -> new UserAuthException(ExceptionMessage.USER_NOT_FOUND)
        ).getProviderId();
    }

    /**
     * 이메일, 비밀번호를 검증 후 일치하는 회원 정보 Entity 반환
     * @param email 사용자가 입력한 이메일
     * @param password 사용자가 입력한 비밀번호
     * @return 알맞는 회원 정보
     */
    private Member authenticate(String email, String password) {
        Optional<Member> memberOptional = memberRepository.findByEmail(email);
        if (memberOptional.isEmpty()) {
            throw new UserAuthException(ExceptionMessage.USER_NOT_FOUND);
        }

        Member member = memberOptional.get();
        if (!passwordEncoder.matches(password, member.getPassword())) {
            throw new UserAuthException(ExceptionMessage.MISMATCH_PASSWORD);
        }

        return member;
    }

    /**
     * RefreshToken의 유효기간을 확인 후, 토큰을 재발급해주는 메소드
     * @param refreshToken 사용자의 RefreshToken
     * @param authentication 사용자의 인증 정보
     * @return 재발급된 accessToken
     */
    private JwtTokenResponse reissueToken(String refreshToken, Authentication authentication) {
        String reissueAccessToken = jwtTokenProvider.reissueToken(refreshToken, authentication);
        return JwtTokenResponse.from(reissueAccessToken);
    }
}
