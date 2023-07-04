package nerds.studiousTestProject.user.service.member;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nerds.studiousTestProject.user.dto.general.signup.SignUpRequest;
import nerds.studiousTestProject.user.dto.general.token.JwtTokenResponse;
import nerds.studiousTestProject.user.entity.member.Member;
import nerds.studiousTestProject.user.entity.member.MemberType;
import nerds.studiousTestProject.user.entity.token.LogoutAccessToken;
import nerds.studiousTestProject.user.entity.token.RefreshToken;
import nerds.studiousTestProject.user.exception.message.ExceptionMessage;
import nerds.studiousTestProject.user.exception.model.UserAuthException;
import nerds.studiousTestProject.user.repository.member.MemberRepository;
import nerds.studiousTestProject.user.service.token.LogoutAccessTokenService;
import nerds.studiousTestProject.user.service.token.RefreshTokenService;
import nerds.studiousTestProject.user.util.JwtTokenProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
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
        MemberType type = MemberType.handle(signUpRequest.getType());
        validate(signUpRequest, type);

        String encode = getEncodedPassword(signUpRequest);
        Member member = Member.builder()
                .email(signUpRequest.getEmail())
                .password(encode)
                .providerId(signUpRequest.getProviderId())
                .name(signUpRequest.getName())
                .nickname(signUpRequest.getNickname())
                .phoneNumber(signUpRequest.getPhoneNumber())
                .birthday(signUpRequest.getBirthday())
                .roles(signUpRequest.getRoles())
                .type(type)
                .createdDate(new Date())
                .usable(true)
                .resignedDate(null)
                .build();

        log.info("created member = {}", member);
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
    public JwtTokenResponse issueToken(String email, String password) {
        List<Member> members = memberRepository.findByEmail(email);
        if (members.isEmpty()) {
            throw new UserAuthException(ExceptionMessage.MISMATCH_EMAIL);
        }

        Member member = members.stream().filter(m -> passwordEncoder.matches(password, m.getPassword())).findAny().orElseThrow(() -> new UserAuthException(ExceptionMessage.MISMATCH_PASSWORD));
        if (!member.getType().equals(MemberType.DEFAULT)) {
            throw new UserAuthException(ExceptionMessage.NOT_DEFAULT_TYPE_USER);
        }

        return jwtTokenProvider.generateToken(member);
    }

    /**
     * 현재 사용자의 토큰을 만료시고 블랙리스트에 저장하는 메소드
     * @param accessToken 사용자의 accessToken
     * @return 현재 사용자의 이메일&타입
     */
    @Transactional
    public String expireToken(String accessToken) {
        String resolvedAccessToken = jwtTokenProvider.resolveToken(accessToken);

        String username = jwtTokenProvider.parseToken(resolvedAccessToken);
        log.info("username = {}", username);

        Long remainTime = jwtTokenProvider.getRemainTime(resolvedAccessToken);
        refreshTokenService.deleteByUsername(username);

        logoutAccessTokenService.saveLogoutAccessToken(LogoutAccessToken.from(username, resolvedAccessToken, remainTime));

        // LogoutDB 가 과부화될 가능성 있음
        return username;
    }

    @Transactional
    public String findEmailFromPhoneNumber(String phoneNumber) {
        Optional<Member> memberOptional = memberRepository.findByPhoneNumber(phoneNumber);
        if (memberOptional.isEmpty()) {
            throw new UserAuthException(ExceptionMessage.USER_NOT_FOUND);
        }

        Member member = memberOptional.get();
        if (!member.getType().equals(MemberType.DEFAULT)) {
            throw new UserAuthException(ExceptionMessage.NOT_DEFAULT_TYPE_USER);
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
        List<Member> members = memberRepository.findByEmail(email);
        if (members.isEmpty()) {
            throw new UserAuthException(ExceptionMessage.MISMATCH_EMAIL);
        }

        Member member = members.stream().filter(m -> m.getPassword().equals(phoneNumber)).findAny().orElseThrow(() -> new UserAuthException(ExceptionMessage.MISMATCH_PHONE_NUMBER));
        if (!member.getType().equals(MemberType.DEFAULT)) {
            throw new UserAuthException(ExceptionMessage.NOT_DEFAULT_TYPE_USER);
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
            throw new UserAuthException(ExceptionMessage.MISMATCH_PASSWORD);
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
            throw new UserAuthException(ExceptionMessage.MISMATCH_PASSWORD);
        }

        member.withdraw();
        expireToken(accessToken);
    }

    /**
     * 사용자가 만료된 accessToken 과 만료되지 않은 refreshToken을 넘길 때 새로운 accessToken을 만들어 주는 메소드
     * RefreshToken의 유효기간을 확인 후, 토큰을 재발급해주는 메소드
     * @param refreshToken 사용자로부터 넘겨 받은 refreshToken
     * @return 새로운 accessToken 이 담긴 JwtTokenResponse 객체
     */
    @Transactional
    public JwtTokenResponse reissueToken(String refreshToken) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getName() == null) {
            log.info("auth = {}", authentication);
            throw new UserAuthException(ExceptionMessage.NOT_AUTHORIZE_ACCESS);
        }

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String username = userDetails.getUsername();
        log.info("username = {}", username);

        RefreshToken redisRefreshToken = refreshTokenService.findByUsername(username);
        if (!refreshToken.equals(redisRefreshToken.getRefreshToken())) {
            log.info("refreshToken = {}", refreshToken);
            log.info("redisRefreshToken = {}", redisRefreshToken.getRefreshToken());
            throw new UserAuthException(ExceptionMessage.MISMATCH_TOKEN);
        }

//        Authorization 사용하여 패스워드 가져올 때 PROTECTED 되있으므로 DB에서 사용자 내역을 가져온다.
//        String password = userDetails.getPassword();
//        참고 : https://djunnni.gitbook.io/springboot/2019-11-30
//        Member member = memberRepository.findById(currentEmail).get();
//        String password = passwordEncoder.encode(member.getPassword());

        String reissueAccessToken = jwtTokenProvider.reissueToken(refreshToken, username, authentication);
        return JwtTokenResponse.from(reissueAccessToken);
    }

    public Optional<Member> findByProviderIdAndType(Long providerId, MemberType type) {
        return memberRepository.findByProviderIdAndType(providerId, type);
    }

    private void validate(SignUpRequest signUpRequest, MemberType type) {
        Long providerId = signUpRequest.getProviderId();
        if (providerId == null && !type.equals(MemberType.DEFAULT)) {
            throw new UserAuthException(ExceptionMessage.NOT_EXIST_PROVIDER_ID);
        }

        if ((providerId != null && memberRepository.existsByProviderIdAndType(providerId, type))) {
            throw new UserAuthException(ExceptionMessage.ALREADY_EXIST_USER);
        }

        if (signUpRequest.getPassword() == null && type.equals(MemberType.DEFAULT)) {
            throw new UserAuthException(ExceptionMessage.NOT_EXIST_PASSWORD);
        }

        String email = signUpRequest.getEmail();
        if (memberRepository.existsByEmailAndType(email, type)) {
            throw new UserAuthException(ExceptionMessage.ALREADY_EXIST_USER);
        }

        String phoneNumber = signUpRequest.getPhoneNumber();
        if (memberRepository.existsByPhoneNumber(phoneNumber)) {
            throw new UserAuthException(ExceptionMessage.PHONE_NUMBER_ALREADY_EXIST);
        }
    }

    /**
     * 인코딩된 비밀번호를 발급해주는 메소드
     * (만약, 소셜 로그인인 경우 UUID를 통한 랜덤 문자열을 인코딩하여 반환)
     * @param signUpRequest 로그인 정보
     * @return 인코딩된 비밀번호
     */
    private String getEncodedPassword(SignUpRequest signUpRequest) {
        String password = signUpRequest.getPassword() == null ? UUID.randomUUID().toString() : signUpRequest.getPassword();
        return passwordEncoder.encode(password);
    }

    private Member getMemberFromAccessToken(String accessToken) {
        String resolvedAccessToken = jwtTokenProvider.resolveToken(accessToken);

        String[] split = jwtTokenProvider.parseToken(resolvedAccessToken).split("&");
        String email = split[0];
        MemberType type = MemberType.valueOf(split[1]);

        return memberRepository.findByEmailAndType(email, type).
                orElseThrow(() -> new UserAuthException(ExceptionMessage.MISMATCH_USERNAME_TOKEN));
    }
}
