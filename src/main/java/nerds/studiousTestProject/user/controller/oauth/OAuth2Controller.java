package nerds.studiousTestProject.user.controller.oauth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nerds.studiousTestProject.user.dto.oauth.token.TokenInfo;
import nerds.studiousTestProject.user.service.oauth.OAuth2Service;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@Slf4j
@RequiredArgsConstructor
@RequestMapping("/oauth")
public class OAuth2Controller {
    private final OAuth2Service oAuth2Service;

    @GetMapping("/authorize/{provider}")
    public TokenInfo authorize(@PathVariable String provider, @RequestParam String code) {
        return oAuth2Service.authorize(provider, code);
    }
}