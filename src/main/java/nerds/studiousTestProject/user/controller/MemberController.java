package nerds.studiousTestProject.user.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nerds.studiousTestProject.user.dto.general.login.MemberLoginRequest;
import nerds.studiousTestProject.user.dto.general.signup.SignUpRequest;
import nerds.studiousTestProject.user.dto.general.token.JwtTokenResponse;
import nerds.studiousTestProject.user.service.member.MemberService;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/members")
public class MemberController {
    private final MemberService memberService;

    @PostMapping("/signup")
    public void signUp(@RequestBody SignUpRequest signUpRequest) {
        memberService.register(signUpRequest);
    }

    @PostMapping("/login")
    public JwtTokenResponse login(@RequestBody MemberLoginRequest memberLoginRequest) {
        return memberService.login(memberLoginRequest.getEmail(), memberLoginRequest.getPassword());
    }

    @GetMapping("/email")
    public String findEmail(@RequestBody String phoneNumber) {
        return memberService.findEmailFromPhoneNumber(phoneNumber);
    }

    @PatchMapping("/nickname")
    public void patchNickname(@RequestHeader(HttpHeaders.AUTHORIZATION) String accessToken, @RequestBody String nickname) {
        memberService.nicknameChange(accessToken, nickname);
    }

    @PostMapping("/logout")
    public String logout(@RequestHeader(HttpHeaders.AUTHORIZATION) String accessToken) {
        return memberService.logout(accessToken);
    }

    @PostMapping("/withdraw")
    public void withdraw(@RequestHeader(HttpHeaders.AUTHORIZATION) String accessToken) {
        memberService.withdraw(accessToken);
    }

    @PostMapping("/reissue")
    public JwtTokenResponse reissue(@CookieValue("refresh_token") String refreshToken) {
        return memberService.reissue(refreshToken);
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
