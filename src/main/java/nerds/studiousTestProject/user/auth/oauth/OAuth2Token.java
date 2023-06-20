package nerds.studiousTestProject.user.auth.oauth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OAuth2Token {
    private String token;
    private String refreshToken;
    private LocalDateTime expiredAt;
}
