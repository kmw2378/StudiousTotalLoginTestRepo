package nerds.studiousTestProject.user.dto.oauth.token;

import lombok.Data;
import lombok.Getter;

@Data

public class OAuth2TokenResponse {
    private String access_token;
    private String refresh_token;
    private Long expires_in;
}
