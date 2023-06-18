package nerds.studiousTestProject.user.dto.general.token;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import nerds.studiousTestProject.user.util.JwtTokenUtil;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class JwtTokenResponse {
    private String grantType;
    private String accessToken;

    public static JwtTokenResponse from(String accessToken) {
        return JwtTokenResponse.builder()
                .grantType(JwtTokenUtil.TOKEN_PREFIX)
                .accessToken(accessToken)
                .build();
    }
}
