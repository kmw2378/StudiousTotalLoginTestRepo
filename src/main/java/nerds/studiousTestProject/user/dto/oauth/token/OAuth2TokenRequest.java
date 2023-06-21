package nerds.studiousTestProject.user.dto.oauth.token;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class OAuth2TokenRequest {
    private String grant_type;
    private String client_id;
    private String client_secret;
    private String code;
    private String state;
    private String redirect_uri;
}
