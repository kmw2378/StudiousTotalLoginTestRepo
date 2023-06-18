package nerds.studiousTestProject.user.repository.token;

import nerds.studiousTestProject.user.entity.token.LogoutAccessToken;
import org.springframework.data.repository.CrudRepository;

public interface LogoutAccessTokenRepository extends CrudRepository<LogoutAccessToken, String> {
}
