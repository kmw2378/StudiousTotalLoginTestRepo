package nerds.studiousTestProject.user.entity.token;

import jakarta.persistence.Column;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

import java.time.LocalDateTime;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@RedisHash("refreshToken")
@Builder
public class RefreshToken {
    @Id
    private String email;

    @Column(name = "refresh_token", unique = true)
    private String refreshToken;

    private LocalDateTime expiration;

    public static RefreshToken from(String email, String refreshToken, LocalDateTime expirationTime) {
        return RefreshToken.builder()
                .email(email)
                .refreshToken(refreshToken)
                .expiration(expirationTime)
                .build();
    }
}
