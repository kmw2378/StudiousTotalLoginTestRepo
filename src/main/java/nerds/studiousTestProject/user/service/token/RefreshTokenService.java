package nerds.studiousTestProject.user.service.token;

import lombok.RequiredArgsConstructor;
import nerds.studiousTestProject.user.entity.token.RefreshToken;
import nerds.studiousTestProject.user.exception.message.ExceptionMessage;
import nerds.studiousTestProject.user.exception.model.TokenNotFoundException;
import nerds.studiousTestProject.user.repository.token.RefreshTokenRepository;
import nerds.studiousTestProject.user.util.DateConverter;
import nerds.studiousTestProject.user.util.JwtTokenUtil;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshToken save(String username, String refreshToken) {
        return refreshTokenRepository.save(
                RefreshToken.from(
                        username,
                        refreshToken,
                        DateConverter.toLocalDateTime(JwtTokenUtil.REFRESH_TOKEN_EXPIRE_TIME)
                )
        );
    }

    public RefreshToken findByUsername(String username) {
        return refreshTokenRepository.findById(username)
                .orElseThrow(() -> new TokenNotFoundException(ExceptionMessage.TOKEN_NOT_FOUND));
    }

    public void deleteByUsername(String username) {
        refreshTokenRepository.deleteById(username);
    }
}
