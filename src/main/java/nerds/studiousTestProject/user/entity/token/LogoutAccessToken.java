package nerds.studiousTestProject.user.entity.token;

import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

@Getter
@Builder
@RedisHash("logoutAccessToken")
@NoArgsConstructor
@AllArgsConstructor
public class LogoutAccessToken {
    @Id
    private String token;
    private String email;

    @TimeToLive
    private Long expiration;

    public static LogoutAccessToken from(String email, String accessToken, Long expirationTime) {
        return LogoutAccessToken.builder()
                .token(accessToken)
                .email(email)
                .expiration(expirationTime / 1000)
                .build();
    }
}
