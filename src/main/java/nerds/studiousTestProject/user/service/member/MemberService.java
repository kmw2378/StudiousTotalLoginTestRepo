package nerds.studiousTestProject.user.service.member;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nerds.studiousTestProject.user.dto.general.find.FindEmailRequest;
import nerds.studiousTestProject.user.dto.general.find.FindEmailResponse;
import nerds.studiousTestProject.user.dto.general.find.FindPasswordRequest;
import nerds.studiousTestProject.user.dto.general.logout.LogoutResponse;
import nerds.studiousTestProject.user.dto.general.find.FindPasswordResponse;
import nerds.studiousTestProject.user.dto.general.patch.PatchNicknameRequest;
import nerds.studiousTestProject.user.dto.general.patch.PatchPasswordRequest;
import nerds.studiousTestProject.user.dto.general.signup.SignUpRequest;
import nerds.studiousTestProject.user.dto.general.token.JwtTokenResponse;
import nerds.studiousTestProject.user.dto.general.withdraw.WithdrawRequest;
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

        if (!member.isUsable()) {
            throw new UserAuthException(ExceptionMessage.EXPIRE_USER);
        }

        return jwtTokenProvider.generateToken(member);
    }

    /**
     * 현재 사용자의 토큰을 만료시고 블랙리스트에 저장하는 메소드
     * @param accessToken 사용자의 accessToken
     * @return 현재 사용자의 PK
     */
    @Transactional
    public LogoutResponse expireToken(String accessToken) {
        String resolvedAccessToken = jwtTokenProvider.resolveToken(accessToken);
        Long memberId = jwtTokenProvider.parseToken(resolvedAccessToken);
        Long remainTime = jwtTokenProvider.getRemainTime(resolvedAccessToken);

        refreshTokenService.deleteByMemberId(memberId);
        logoutAccessTokenService.saveLogoutAccessToken(LogoutAccessToken.from(resolvedAccessToken, remainTime));

        // LogoutDB 가 과부화될 가능성 있음 => 토큰 유효기간이 만료되면 자동 삭제되므로 염려할 필요 X
        return LogoutResponse.builder()
                .memberId(memberId)
                .build();
    }

    @Transactional
    public FindEmailResponse findEmailFromPhoneNumber(FindEmailRequest findEmailRequest) {
        String phoneNumber = findEmailRequest.getPhoneNumber();

        Member member = memberRepository.findByPhoneNumber(phoneNumber).
                orElseThrow(() -> new UserAuthException(ExceptionMessage.USER_NOT_FOUND));

        if (!member.getType().equals(MemberType.DEFAULT)) {
            throw new UserAuthException(ExceptionMessage.NOT_DEFAULT_TYPE_USER);
        }

        return FindEmailResponse.builder()
                .email(member.getEmail())
                .build();
    }

    /**
     * 이메일과 전화번호를 통해 알맞는 회원의 비밀번호를 임시 비밀번호로 수정 및 임시 비밀번호를 반환하는 메소드
     * @param email 이메일
     * @param phoneNumber 전화번호
     * @return 발급된 임시 비밀번호
     */
    @Transactional
    public FindPasswordResponse issueTemporaryPassword(FindPasswordRequest findPasswordRequest) {
        String email = findPasswordRequest.getEmail();
        String phoneNumber = findPasswordRequest.getPhoneNumber();

        List<Member> members = memberRepository.findByEmail(email);
        if (members.isEmpty()) {
            throw new UserAuthException(ExceptionMessage.MISMATCH_EMAIL);
        }

        Member member = members.stream().filter(m -> m.getPhoneNumber().equals(phoneNumber)).findAny()
                .orElseThrow(() -> new UserAuthException(ExceptionMessage.MISMATCH_PHONE_NUMBER));
        if (!member.getType().equals(MemberType.DEFAULT)) {
            throw new UserAuthException(ExceptionMessage.NOT_DEFAULT_TYPE_USER);
        }

        String temporaryPassword = UUID.randomUUID().toString().substring(0, 8);
        String encode = passwordEncoder.encode(temporaryPassword);
        member.updatePassword(encode);

        return FindPasswordResponse.builder()
                .tempPassword(temporaryPassword)
                .build();
    }

    @Transactional
    public void replacePassword(String accessToken, PatchPasswordRequest patchPasswordRequest) {
        String oldPassword = patchPasswordRequest.getOldPassword();
        String newPassword = patchPasswordRequest.getNewPassword();

        Member member = getMemberFromAccessToken(accessToken);
        if (!passwordEncoder.matches(oldPassword, member.getPassword())) {
            throw new UserAuthException(ExceptionMessage.MISMATCH_PASSWORD);
        }

        // 회원 비밀번호 수정
        String encode = passwordEncoder.encode(newPassword);
        member.updatePassword(encode);
    }

    @Transactional
    public void replaceNickname(String accessToken, PatchNicknameRequest patchNicknameRequest) {
        Member member = getMemberFromAccessToken(accessToken);
        member.updateNickname(patchNicknameRequest.getNewNickname());
    }

    @Transactional
    public void deactivate(String accessToken, WithdrawRequest withdrawRequest) {
        String password = withdrawRequest.getPassword();

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
     *
     * @param accessToken
     * @param refreshToken 사용자로부터 넘겨 받은 refreshToken
     * @return 새로운 accessToken 이 담긴 JwtTokenResponse 객체
     */
    @Transactional
    public JwtTokenResponse reissueToken(String accessToken, String refreshToken) {
        Member member = getMemberFromAccessToken(accessToken);
        RefreshToken redisRefreshToken = refreshTokenService.findByMemberId(member.getId());
        if (redisRefreshToken == null) {
            throw new UserAuthException(ExceptionMessage.TOKEN_VALID_TIME_EXPIRED);
        }

        if (!refreshToken.equals(redisRefreshToken.getToken())) {
            log.info("refreshToken = {}", refreshToken);
            log.info("redisRefreshToken = {}", redisRefreshToken.getToken());
            throw new UserAuthException(ExceptionMessage.MISMATCH_TOKEN);
        }

//        Authorization 사용하여 패스워드 가져올 때 PROTECTED 되있으므로 DB에서 사용자 내역을 가져온다.
//        String password = userDetails.getPassword();
//        참고 : https://djunnni.gitbook.io/springboot/2019-11-30
//        Member member = memberRepository.findById(currentEmail).get();
//        String password = passwordEncoder.encode(member.getPassword());

        return jwtTokenProvider.generateToken(member);
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
        Long memberId = jwtTokenProvider.parseToken(resolvedAccessToken);

        Member member =  memberRepository.findById(memberId).
                orElseThrow(() -> new UserAuthException(ExceptionMessage.MISMATCH_USERNAME_TOKEN));

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getName() == null) {
            log.info("auth = {}", authentication);
            throw new UserAuthException(ExceptionMessage.NOT_AUTHORIZE_ACCESS);
        }

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        if (!userDetails.getUsername().equals(member.getUsername())) {
            throw new UserAuthException(ExceptionMessage.NOT_AUTHORIZE_ACCESS);
        }

        return member;
    }
}