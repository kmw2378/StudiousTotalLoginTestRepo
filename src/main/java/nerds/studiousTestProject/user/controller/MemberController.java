package nerds.studiousTestProject.user.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nerds.studiousTestProject.user.dto.general.find.FindEmailRequest;
import nerds.studiousTestProject.user.dto.general.find.FindEmailResponse;
import nerds.studiousTestProject.user.dto.general.find.FindPasswordRequest;
import nerds.studiousTestProject.user.dto.general.find.FindPasswordResponse;
import nerds.studiousTestProject.user.dto.general.login.LoginRequest;
import nerds.studiousTestProject.user.dto.general.logout.LogoutResponse;
import nerds.studiousTestProject.user.dto.general.signup.SignUpRequest;
import nerds.studiousTestProject.user.dto.general.token.JwtTokenResponse;
import nerds.studiousTestProject.user.service.member.MemberService;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/studious/members")
public class MemberController {
    private final MemberService memberService;

    @PostMapping("/signup")
    public JwtTokenResponse signUp(@RequestBody SignUpRequest signUpRequest) {
        return memberService.register(signUpRequest);
    }

    @PostMapping("/login")
    public JwtTokenResponse login(@RequestBody LoginRequest loginRequest) {
        return memberService.issueToken(loginRequest.getEmail(), loginRequest.getPassword());
    }

    @GetMapping("/email")
    public FindEmailResponse findEmail(@RequestBody FindEmailRequest findEmailRequest) {
        return memberService.findEmailFromPhoneNumber(findEmailRequest);
    }

    @PostMapping("/password")
    public FindPasswordResponse findPassword(@RequestBody FindPasswordRequest findPasswordRequest) {
        log.info("email = {}", findPasswordRequest.getEmail());
        log.info("phoneNumber = {}", findPasswordRequest.getPhoneNumber());
        return memberService.issueTemporaryPassword(findPasswordRequest);
    }

    @PostMapping("/logout")
    public LogoutResponse logout(@RequestHeader(HttpHeaders.AUTHORIZATION) String accessToken) {
        return memberService.expireToken(accessToken);
    }

    @PostMapping("/reissue")
    public JwtTokenResponse reissue(@RequestHeader(HttpHeaders.AUTHORIZATION) String accessToken, @CookieValue("refresh_token") String refreshToken) {
        return memberService.reissueToken(accessToken, refreshToken);
    }

    /**
     * USER 권한에서 잘 실행되는지 테스트하기 위한 메소드
     * @return
     */
    @ResponseBody
    @GetMapping("/test")
    public String test() {
        return "success";
    }
}
