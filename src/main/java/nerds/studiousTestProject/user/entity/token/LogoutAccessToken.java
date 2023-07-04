package nerds.studiousTestProject.user.entity.token;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
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
    private String username;

    @TimeToLive
    private Long expiration;

    public static LogoutAccessToken from(String username, String accessToken, Long expirationTime) {
        return LogoutAccessToken.builder()
                .token(accessToken)
                .username(username)
                .expiration(expirationTime / 1000)
                .build();
    }
}
