package nerds.studiousTestProject.user.repository.oauth;

import nerds.studiousTestProject.user.entity.oauth.OAuth2Token;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OAuth2TokenRepository extends JpaRepository<OAuth2Token, Long> {
    Optional<OAuth2Token> findByEmail(String email);
}
