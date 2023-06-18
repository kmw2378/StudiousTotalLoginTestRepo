package nerds.studiousTestProject.user.dto.code;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class KakaoUserLoginResponse {
    private String email;
    private String role;
    private String tokenType;
    private String accessToken;
    private String refreshToken;
}
