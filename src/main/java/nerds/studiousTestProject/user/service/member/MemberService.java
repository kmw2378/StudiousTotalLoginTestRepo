package nerds.studiousTestProject.user.service.member;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nerds.studiousTestProject.user.entity.member.MemberType;
import nerds.studiousTestProject.user.dto.general.signup.SignUpRequest;
import nerds.studiousTestProject.user.dto.general.token.JwtTokenResponse;
import nerds.studiousTestProject.user.entity.member.Member;
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

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

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
     * @param signUpRequest 회원 가입 폼에서 입력한 정보
     *                      이 때, MemberType은 프론트에서 이전에 백으로 부터 전달받은 값 (없다면 null)
     * @return 회원가입한 정보로 만든 토큰 값
     */
    @Transactional
    public JwtTokenResponse register(SignUpRequest signUpRequest) {
        Long providerId = signUpRequest.getProviderId();
        String email = signUpRequest.getEmail();

        if ((providerId != null && memberRepository.existsByProviderId(providerId)) || memberRepository.existsByEmail(email)) {
            throw new UserAuthException(ExceptionMessage.ALREADY_EXIST_USER);
        }

        String phoneNumber = signUpRequest.getPhoneNumber();
        if (memberRepository.existsByPhoneNumber(phoneNumber)) {
            throw new UserAuthException(ExceptionMessage.PHONE_NUMBER_ALREADY_EXIST);
        }

        // 만약, MemberType이 null 인 경우를 프론트에서 처리할지 백에서 처리할지 고민
        // 그냥 백에서 처리하자.
        MemberType type = signUpRequest.getType();
        if (type == null) {
            type = MemberType.DEFAULT;
        }

        String password = signUpRequest.getPassword();
        String encode = passwordEncoder.encode(password);
        Member member = Member.builder()
                .email(email)
                .password(encode)
                .providerId(providerId)
                .name(signUpRequest.getName())
                .nickname(signUpRequest.getNickname())
                .phoneNumber(phoneNumber)
                .birthday(signUpRequest.getBirthday())
                .roles(signUpRequest.getRoles())
                .type(type)
                .createdDate(new Date())
                .usable(true)
                .resignedDate(null)
                .build();
        log.info("member = {}", member);
        memberRepository.save(member);
        return jwtTokenProvider.generateToken(member);
    }

    /**
     * 로그인 하는 시점에 토큰을 생성해서 반환하는 메소드 (로그인을 하는 시점에 토큰이 생성된다)
     * @param email 사용자 이메일
     * @param password 사용자 비밀번호
     * @return 발급한 토큰 정보
     */
    @Transactional
    public JwtTokenResponse login(String email, String password) {
        Optional<Member> memberOptional = memberRepository.findByEmail(email);

        if (memberOptional.isEmpty()) {
            throw new UserAuthException(ExceptionMessage.MISMATCH_EMAIL);
        }

        Member member = memberOptional.get();
        if (!passwordEncoder.matches(password, member.getPassword())) {
            throw new UserAuthException(ExceptionMessage.MISMATCH_PASSWORD);
        }

        if (!member.getType().equals(MemberType.DEFAULT)) {
            throw new UserAuthException(ExceptionMessage.NOT_DEFAULT_TYPE_USER);
        }

        return jwtTokenProvider.generateToken(member);
    }

    /**
     * 현재 사용자의 토큰을 만료시고 블랙리스트에 저장하는 메소드
     * @param accessToken 사용자의 accessToken
     * @return 현재 사용자의 이메일
     */
    @Transactional
    public String logout(String accessToken) {
        String resolvedAccessToken = jwtTokenProvider.resolveToken(accessToken);

        String email = jwtTokenProvider.parseToken(resolvedAccessToken);
        log.info("email = {}", email);

        Long remainTime = jwtTokenProvider.getRemainTime(resolvedAccessToken);
        refreshTokenService.deleteByEmail(email);

        logoutAccessTokenService.saveLogoutAccessToken(LogoutAccessToken.from(email, resolvedAccessToken, remainTime));

        // LogoutDB 가 과부화될 가능성 있음
        return email;
    }

    @Transactional
    public String findEmailFromPhoneNumber(String phoneNumber) {
        Optional<Member> memberOptional = memberRepository.findByPhoneNumber(phoneNumber);
        if (memberOptional.isEmpty()) {
            throw new RuntimeException("일치하는 회원 정보가 없습니다.");
        }

        Member member = memberOptional.get();
        if (!member.getType().equals(MemberType.DEFAULT)) {
            throw new RuntimeException("소셜 연동 계정 입니다. 소셜 로그인을 이용해주세요.");
        }

        return member.getEmail();
    }

    /**
     * 이메일과 전화번호를 통해 알맞는 회원의 비밀번호를 임시 비밀번호로 수정 및 임시 비밀번호를 반환하는 메소드
     * @param email 이메일
     * @param phoneNumber 전화번호
     * @return 발급된 임시 비밀번호
     */
    @Transactional
    public String issueTemporaryPassword(String email, String phoneNumber) {
        Optional<Member> memberOptional = memberRepository.findByEmail(email);
        if (memberOptional.isEmpty()) {
            throw new RuntimeException("이메일 정보가 올바르지 않습니다.");
        }

        Member member = memberOptional.get();

        if (!member.getType().equals(MemberType.DEFAULT)) {
            throw new RuntimeException("소셜 연동 계정 입니다. 소셜 로그인을 이용해주세요.");
        }

        if (member.getPhoneNumber().equals(phoneNumber)) {
            throw new RuntimeException("이메일과 전화 번호가 일치하지 않습니다.");
        }

        String temporaryPassword = UUID.randomUUID().toString().substring(0, 8);
        String encode = passwordEncoder.encode(temporaryPassword);
        member.updatePassword(encode);

        return temporaryPassword;
    }

    @Transactional
    public void replacePassword(String accessToken, String oldPassword, String newPassword) {
        Member member = getMemberFromAccessToken(accessToken);
        if (!passwordEncoder.matches(oldPassword, member.getPassword())) {
            throw new RuntimeException("기존 비밀번호가 일치하지 않습니다.");
        }

        // 회원 비밀번호 수정
        String encode = passwordEncoder.encode(newPassword);
        member.updatePassword(encode);
    }

    @Transactional
    public void replaceNickname(String accessToken, String nickname) {
        Member member = getMemberFromAccessToken(accessToken);
        member.updateNickname(nickname);
    }

    @Transactional
    public void deactivate(String accessToken, String password) {
        Member member = getMemberFromAccessToken(accessToken);
        if (!passwordEncoder.matches(password, member.getPassword())) {
            throw new RuntimeException("비밀번호가 일치하지 않습니다.");
        }

        member.withdraw();
        expireToken(accessToken);
    }

    /**
     * 사용자가 만료된 accessToken 과 만료되지 않은 refreshToken을 넘길 때 새로운 accessToken을 만들어 주는 메소드
     * @param refreshToken 사용자로부터 넘겨 받은 refreshToken
     * @return 새로운 accessToken 이 담긴 JwtTokenResponse 객체
     */
    @Transactional
    public JwtTokenResponse reissue(String refreshToken) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getName() == null) {
            log.info("auth = {}", authentication);
            throw new UserAuthException(ExceptionMessage.NOT_AUTHORIZE_ACCESS);
        }

        String currentEmail = authentication.getName();
        log.info("currentEmail = {}", currentEmail);
        RefreshToken redisRefreshToken = refreshTokenService.findByEmail(currentEmail);
        if (!refreshToken.equals(redisRefreshToken.getRefreshToken())) {
            log.info("refreshToken = {}", refreshToken);
            log.info("redisRefreshToken = {}", redisRefreshToken.getRefreshToken());
            throw new TokenCheckFailException(ExceptionMessage.MISMATCH_TOKEN);
        }

//        Authorization 사용하여 패스워드 가져올 때 PROTECTED 되있으므로 DB에서 사용자 내역을 가져온다.
//        String password = userDetails.getPassword();
//        참고 : https://djunnni.gitbook.io/springboot/2019-11-30
//        Member member = memberRepository.findById(currentEmail).get();
//        String password = passwordEncoder.encode(member.getPassword());

        return reissueToken(refreshToken, authentication);
    }

    public Optional<Member> findByProviderId(Long providerId) {
        return memberRepository.findByProviderId(providerId);
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
