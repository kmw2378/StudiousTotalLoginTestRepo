package nerds.studiousTestProject.user.service.token;

import lombok.RequiredArgsConstructor;
import nerds.studiousTestProject.user.auth.oauth.OAuth2Token;
import nerds.studiousTestProject.user.auth.oauth.userinfo.OAuth2UserInfo;
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

    public RefreshToken saveRefreshTokenFromOAuth2(OAuth2Token oAuth2Token, OAuth2UserInfo oAuth2UserInfo) {
        return refreshTokenRepository.save(
                RefreshToken.from(
                        oAuth2UserInfo.getEmail(),
                        oAuth2Token.getRefreshToken(),
                        oAuth2Token.getExpiredAt()
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
