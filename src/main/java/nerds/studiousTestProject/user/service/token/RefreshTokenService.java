package nerds.studiousTestProject.user.service.token;

import lombok.RequiredArgsConstructor;
import nerds.studiousTestProject.user.entity.token.RefreshToken;
import nerds.studiousTestProject.user.exception.message.ExceptionMessage;
import nerds.studiousTestProject.user.exception.model.TokenNotFoundException;
import nerds.studiousTestProject.user.repository.token.RefreshTokenRepository;
import nerds.studiousTestProject.user.util.DateConverter;
import nerds.studiousTestProject.user.util.JwtTokenProvider;
import nerds.studiousTestProject.user.util.JwtTokenUtil;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;

    public RefreshToken saveRefreshToken(String email) {
        return refreshTokenRepository.save(
                RefreshToken.from(
                        email,
                        jwtTokenProvider.createRefreshToken(),
                        DateConverter.toLocalDateTime(JwtTokenUtil.REFRESH_TOKEN_EXPIRE_TIME)
                )
        );
    }

    public RefreshToken findRefreshTokenByEmail(String email) {
        return refreshTokenRepository.findById(email)
                .orElseThrow(() -> new TokenNotFoundException(ExceptionMessage.TOKEN_NOT_FOUND));
    }

    public void deleteRefreshTokenByEmail(String email) {
        refreshTokenRepository.deleteById(email);
    }
}
