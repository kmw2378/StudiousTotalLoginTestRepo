package nerds.studiousTestProject.user.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import nerds.studiousTestProject.user.dto.general.token.JwtTokenResponse;
import nerds.studiousTestProject.user.entity.member.Member;
import nerds.studiousTestProject.user.entity.token.RefreshToken;
import nerds.studiousTestProject.user.exception.message.ExceptionMessage;
import nerds.studiousTestProject.user.exception.model.TokenCheckFailException;
import nerds.studiousTestProject.user.exception.model.UserAuthException;
import nerds.studiousTestProject.user.service.token.LogoutAccessTokenService;
import nerds.studiousTestProject.user.service.token.RefreshTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.security.Key;
import java.util.Collection;
import java.util.Date;

@Slf4j
@Component
public class JwtTokenProvider {
    private final Key key;
    private final RefreshTokenService refreshTokenService;
    private final UserDetailsService userDetailsService;
    private final LogoutAccessTokenService logoutAccessTokenService;

    @Autowired
    public JwtTokenProvider(@Value("${spring.jwt.secret}") String secretKey,
                            RefreshTokenService refreshTokenService,
                            LogoutAccessTokenService logoutAccessTokenService,
                            UserDetailsService userDetailsService
    ) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.refreshTokenService = refreshTokenService;
        this.logoutAccessTokenService = logoutAccessTokenService;
        this.userDetailsService = userDetailsService;
    }

    public JwtTokenResponse generateToken(Member member) {
        // 1. 토큰 생성
        String accessToken = createAccessToken(member);
        RefreshToken refreshToken = refreshTokenService.save(member.getEmail(), createRefreshToken());

        // 2. 쿠키에 Refresh 토큰 등록
        setRefreshTokenAtCookie(refreshToken);

        // 3. 생성한 토큰을 DTO에 담아 반환
        return JwtTokenResponse.from(accessToken);
    }

    /**
     * JWT 토큰을 복호하하여 토큰에 들어있는 정보를 꺼내는 메소드
     * @return UserDetails 객체를 통해 만든 Authentication
     */
    public Authentication getAuthentication(String accessToken) {
        String username = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody().getSubject();
        if (username == null) {
            throw new TokenCheckFailException(ExceptionMessage.NOT_AUTHORIZE_ACCESS);
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public String reissueToken(String refreshToken, String username, Authentication authentication) {
        if (lessThanReissueExpirationTimesLeft(refreshToken)) {
            throw new UserAuthException(ExceptionMessage.NOT_EXPIRED_REFRESH_TOKEN);
        }

        RefreshToken newRedisToken = refreshTokenService.save(username, createRefreshToken());
        setRefreshTokenAtCookie(newRedisToken);
        return createAccessToken(username, authentication.getAuthorities());
    }

    private String createAccessToken(Member member) {
        return createAccessToken(member.getUsername(), member.getAuthorities());
    }

    private String createAccessToken(String username, Collection<? extends GrantedAuthority> authorities) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put(JwtTokenUtil.CLAIMS_AUTH, authorities);

        Date now = new Date();

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)    // 토큰 발행 시간
                .setExpiration(new Date(now.getTime() + JwtTokenUtil.ACCESS_TOKEN_EXPIRE_TIME)) // 만료시간 : 현재 + 1시간
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    private String createRefreshToken() {
        Date now = new Date();

        return Jwts.builder()
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + JwtTokenUtil.REFRESH_TOKEN_EXPIRE_TIME))    // 만료 시간 : 현재 + 6시간
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    private boolean lessThanReissueExpirationTimesLeft(String refreshToken) {
        return getRemainTime(refreshToken) < JwtTokenUtil.REISSUE_EXPIRE_TIME;
    }

    public String resolveToken(String token) {
        if (StringUtils.hasText(token) && token.startsWith(JwtTokenUtil.TOKEN_PREFIX + " ")) {
            return token.substring(JwtTokenUtil.TOKEN_PREFIX.length() + 1);
        }

        return null;
    }

    /**
     * 토큰 정보를 검증하는 메소드
     * @param token 토큰
     * @return 토큰 유효성
     */
    public boolean validateToken(String token) {
        if (checkLogout(token)) {
            log.info("로그아웃 된 계정입니다.");
            return false;
        }
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            log.info("msg = {}", ExceptionMessage.INVALID_TOKEN.message());
        } catch (ExpiredJwtException e) {
            log.info("msg = {}", ExceptionMessage.TOKEN_VALID_TIME_EXPIRED);
        } catch (UnsupportedJwtException e) {
            log.info("msg = {}", ExceptionMessage.NOT_SUPPORTED_JWT);
        } catch (IllegalArgumentException e) {
            log.info("msg = {}", ExceptionMessage.TOKEN_NOT_FOUND);
        }

        return false;
    }

    /**
     * 토큰 파싱 메소드
     * @param accessToken 토큰
     * @return Claims 객체
     */
    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

    public String parseToken(String accessToken) {
        return parseClaims(accessToken).getSubject();
    }

    public void setRefreshTokenAtCookie(RefreshToken refreshToken) {
        Cookie cookie = new Cookie(JwtTokenUtil.TOKEN_TYPE_REFRESH, refreshToken.getRefreshToken());
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setMaxAge(refreshToken.getExpiration().getSecond());

        HttpServletResponse response = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getResponse();
        response.addCookie(cookie);
    }

    public Long getRemainTime(String token) {
        Date expiration = parseClaims(token).getExpiration();
        Date now = new Date();
        return expiration.getTime() - now.getTime();
    }

    private boolean checkLogout(String token) {
        return logoutAccessTokenService.existsLogoutAccessTokenById(token);
    }
}
