package nerds.studiousTestProject.user.controller.oauth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nerds.studiousTestProject.user.dto.general.token.JwtTokenResponse;
import nerds.studiousTestProject.user.service.oauth.OAuth2Service;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@Slf4j
@RequiredArgsConstructor
@RequestMapping("/oauth")
public class OAuth2Controller {
    private final OAuth2Service oAuth2Service;

    // 추후 팩토리 클래스를 통해 알맞는 소셜 서비스를 사용하도록 설정 (현재는 그냥 카카오만)
    @PostMapping("/authorize/{provider}")
    public JwtTokenResponse authorize(@PathVariable String provider, @RequestParam String code) {
        log.info("code = {}", code);
        return oAuth2Service.authorize(provider, code);
    }

    @PostMapping("/logout/{provider}")
    public void logout(@RequestHeader(HttpHeaders.AUTHORIZATION) String accessToken, @PathVariable String provider) {
        oAuth2Service.logout(accessToken, provider);
    }
}