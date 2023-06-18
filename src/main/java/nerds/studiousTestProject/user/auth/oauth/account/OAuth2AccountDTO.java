package nerds.studiousTestProject.user.auth.oauth.account;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import nerds.studiousTestProject.user.auth.oauth.OAuth2Token;

import java.time.LocalDateTime;

@Getter
@Setter
public class OAuth2AccountDTO {
    private String provider;
    private String providerId;
    private LocalDateTime createAt;
    private OAuth2Token oAuth2Token;

    @Builder
    public OAuth2AccountDTO(String provider, String providerId, String token, String refreshToken, LocalDateTime createAt, LocalDateTime tokenExpiredAt) {
        this.provider = provider;
        this.providerId = providerId;
        this.createAt = createAt;
        this.oAuth2Token = new OAuth2Token(token, refreshToken, tokenExpiredAt);
    }
}
