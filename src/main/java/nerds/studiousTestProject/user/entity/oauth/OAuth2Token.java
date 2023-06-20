package nerds.studiousTestProject.user.entity.oauth;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToOne;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import nerds.studiousTestProject.user.entity.Member;

import java.time.LocalDateTime;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class OAuth2Token {
    @Id
    private String email;
    private String accessToken;
    private String refreshToken;
    private LocalDateTime expiredAt;

    @OneToOne(mappedBy = "oAuth2Token")
    private Member member;
}
