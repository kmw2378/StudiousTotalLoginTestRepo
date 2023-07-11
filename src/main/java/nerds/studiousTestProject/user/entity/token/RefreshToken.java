package nerds.studiousTestProject.user.entity.token;

import jakarta.persistence.Column;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

import java.time.LocalDateTime;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@RedisHash("refresh_token")
@Builder
public class RefreshToken {
    @Id
    @Column(name = "member_id", unique = true)
    private Long memberId;

    @Column(unique = true)
    private String token;

    @TimeToLive
    private Long expiration;

    public static RefreshToken from(Long memberId, String token, Long expirationTime) {
        return RefreshToken.builder()
                .memberId(memberId)
                .token(token)
                .expiration(expirationTime)
                .build();
    }
}
