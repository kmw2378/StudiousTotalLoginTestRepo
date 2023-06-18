package nerds.studiousTestProject.user.dto.oauth;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class OAuth2LoginRequest {
    private String email;
    private String password;
}
