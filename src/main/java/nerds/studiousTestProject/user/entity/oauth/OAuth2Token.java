package nerds.studiousTestProject.user.entity.oauth;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.time.LocalDateTime;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@ToString
public class OAuth2Token {
    @Id
    private Long providerId;
    private String accessToken;
    private String refreshToken;
    private LocalDateTime expiredAt;
}
