package nerds.studiousTestProject.user.service.token;

import lombok.RequiredArgsConstructor;
import nerds.studiousTestProject.user.entity.token.LogoutAccessToken;
import nerds.studiousTestProject.user.repository.token.LogoutAccessTokenRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutAccessTokenService {
    private final LogoutAccessTokenRepository logoutAccessTokenRepository;

    public void saveLogoutAccessToken(LogoutAccessToken logoutAccessToken) {
        logoutAccessTokenRepository.save(logoutAccessToken);
    }

    public boolean existsLogoutAccessTokenById(String accessToken) {
        return logoutAccessTokenRepository.existsById(accessToken);
    }
}
