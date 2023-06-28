package nerds.studiousTestProject.user.controller.oauth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nerds.studiousTestProject.user.dto.oauth.signup.OAuth2AuthenticateResponse;
import nerds.studiousTestProject.user.service.oauth.OAuth2Service;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequiredArgsConstructor
@RequestMapping("/oauth")
public class OAuth2Controller {
    private final OAuth2Service oAuth2Service;

    @PostMapping("/authenticate/{provider}")
    public OAuth2AuthenticateResponse authenticate(@PathVariable String provider, @RequestParam String code) {
        log.info("code = {}", code);
        return oAuth2Service.authenticate(provider, code);
    }
}