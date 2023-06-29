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
    public JwtTokenResponse signUp(@RequestBody SignUpRequest signUpRequest) {
        return memberService.register(signUpRequest);
    }

    @PostMapping("/login")
    public JwtTokenResponse login(@RequestBody MemberLoginRequest memberLoginRequest) {
        return memberService.issueToken(memberLoginRequest.getEmail(), memberLoginRequest.getPassword());
    }

    @GetMapping("/email")
    public String findEmail(@RequestBody String phoneNumber) {
        return memberService.findEmailFromPhoneNumber(phoneNumber);
    }

    @PostMapping("/password")
    public String findPassword(@RequestBody String email, @RequestBody String phoneNumber) {
        return memberService.issueTemporaryPassword(email, phoneNumber);
    }

    @PatchMapping("/nickname")
    public void patchNickname(@RequestHeader(HttpHeaders.AUTHORIZATION) String accessToken, @RequestBody String newNickname) {
        memberService.replaceNickname(accessToken, newNickname);
    }

    @PatchMapping("/password")
    public void patchPassword(@RequestHeader(HttpHeaders.AUTHORIZATION) String accessToken, @RequestBody String oldPassword, @RequestBody String newPassword) {
        memberService.replacePassword(accessToken, oldPassword, newPassword);
    }

    @PostMapping("/logout")
    public String logout(@RequestHeader(HttpHeaders.AUTHORIZATION) String accessToken) {
        return memberService.expireToken(accessToken);
    }

    @PostMapping("/withdraw")
    public void withdraw(@RequestHeader(HttpHeaders.AUTHORIZATION) String accessToken, @RequestBody String password) {
        memberService.deactivate(accessToken, password);
    }

    @PostMapping("/reissue")
    public JwtTokenResponse reissue(@CookieValue("refresh_token") String refreshToken) {
        return memberService.reissueToken(refreshToken);
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
