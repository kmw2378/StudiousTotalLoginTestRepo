package nerds.studiousTestProject.user.dto.oauth;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class KakaoTokenRequest {
    private String grant_type;
    private String client_id;
    private String redirect_uri;
    private String code;
//    private String client_secret;
}
