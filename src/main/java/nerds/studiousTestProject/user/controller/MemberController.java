package nerds.studiousTestProject.user.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nerds.studiousTestProject.user.dto.general.MemberLoginRequest;
import nerds.studiousTestProject.user.dto.general.MemberSignUpRequest;
import nerds.studiousTestProject.user.dto.general.MemberSignUpResponse;
import nerds.studiousTestProject.user.dto.general.token.JwtTokenResponse;
import nerds.studiousTestProject.user.service.member.MemberService;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/members")
public class MemberController {
    private final MemberService memberService;

    @CrossOrigin(origins = "*")
    @PostMapping("/signup")
    public MemberSignUpResponse signUp(@RequestBody MemberSignUpRequest memberSignUpRequest) {
        return memberService.register(memberSignUpRequest);
    }

    @PostMapping("/login")
    public JwtTokenResponse login(@RequestBody MemberLoginRequest memberLoginRequest) {
        return memberService.login(memberLoginRequest);
    }

    @PostMapping("/logout")
    public void logout(@RequestHeader(HttpHeaders.AUTHORIZATION) String accessToken) {
        memberService.logout(accessToken);
    }

    @PostMapping("/reissue")
    public JwtTokenResponse reissue(@CookieValue("refresh_token") String refreshToken) {
        return memberService.reissue(refreshToken);
    }

    @GetMapping("/test")
    public String test() {
        return "success";
    }
}
