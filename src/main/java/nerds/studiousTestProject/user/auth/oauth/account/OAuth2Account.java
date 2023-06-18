package nerds.studiousTestProject.user.auth.oauth.account;

import io.jsonwebtoken.lang.Assert;
import jakarta.persistence.Entity;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import nerds.studiousTestProject.user.entity.Member;

import java.time.LocalDateTime;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "TBL_OAUTH_ACCOUNT", uniqueConstraints = {@UniqueConstraint(columnNames = {"provider", "providerId"})})
public class OAuth2Account extends BaseEntity {
    private String providerId;
    private String provider;
    private String token;
    private String refreshToken;
    private LocalDateTime tokenExpiredAt;

    @OneToOne(mappedBy = "social")
    private Member member;

    @Builder
    public OAuth2Account(String providerId, String provider, String token, String refreshToken, LocalDateTime tokenExpiredAt) {
        this.providerId = providerId;
        this.provider = provider;
        this.token = token;
        this.refreshToken = refreshToken;
        this.tokenExpiredAt = tokenExpiredAt;
    }

    public void updateToken(String token, String refreshToken, LocalDateTime tokenExpiredAt) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.tokenExpiredAt = tokenExpiredAt;
    }

    public void linkUser(Member member) {
        Assert.state(this.member == null, "소셜 계정에 연동된 다른 계정이 존재합니다.");
        this.member = member;
    }

    public void unlinkUser() {
        Assert.state(this.member != null, "연동된 계정이 존재하지 않습니다.");
        this.member = null;
    }

    public OAuth2AccountDTO toDTO() {
        return OAuth2AccountDTO.builder()
                .provider(provider)
                .providerId(providerId)
                .createAt(getCreateAt())
                .token(token)
                .refreshToken(refreshToken)
                .tokenExpiredAt(tokenExpiredAt)
                .build();
    }
}
