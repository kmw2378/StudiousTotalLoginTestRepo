package nerds.studiousTestProject.user.repository.token;

import nerds.studiousTestProject.user.entity.token.RefreshToken;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends CrudRepository<RefreshToken, String> {
}
