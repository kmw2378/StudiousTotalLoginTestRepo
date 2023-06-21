package nerds.studiousTestProject.user.dto.oauth.token.kakao;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class KakaoTokenRequest {
    private String grant_type;
    private String client_id;
    private String client_secret;
    private String redirect_uri;     // 카카오만 유일
    private String code;
}
