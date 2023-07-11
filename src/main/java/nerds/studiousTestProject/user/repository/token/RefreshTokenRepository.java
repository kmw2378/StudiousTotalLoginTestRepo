package nerds.studiousTestProject.user.repository.token;

import nerds.studiousTestProject.user.entity.token.RefreshToken;
import org.springframework.data.repository.CrudRepository;

public interface RefreshTokenRepository extends CrudRepository<RefreshToken, Long> {
}
