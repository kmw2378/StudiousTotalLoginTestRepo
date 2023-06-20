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
import nerds.studiousTestProject.user.entity.token.RefreshToken;
import nerds.studiousTestProject.user.exception.message.ExceptionMessage;
import nerds.studiousTestProject.user.exception.model.TokenCheckFailException;
import nerds.studiousTestProject.user.service.token.LogoutAccessTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtTokenProvider {
    private final Key key;
    private final LogoutAccessTokenService logoutAccessTokenService;

    @Autowired
    public JwtTokenProvider(@Value("${spring.jwt.secret}") String secretKey,
                            LogoutAccessTokenService logoutAccessTokenService) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.logoutAccessTokenService = logoutAccessTokenService;
    }
    public String createRefreshToken() {
        return Jwts.builder()
                .setExpiration(getRefreshTokenExpiresIn())
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String createAccessToken(Authentication authentication) {
        // 권한 가져오기
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(JwtTokenUtil.CLAIMS_AUTH, authorities)
                .setExpiration(getAccessTokenExpiresIn())
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * JWT 토큰을 복호하하여 토큰에 들어있는 정보를 꺼내는 메소드
     * @return UserDetails 객체를 통해 만든 Authentication
     */
    public Authentication getAuthentication(String accessToken) {
        Claims claims = parseClaims(accessToken);

        if (claims.get(JwtTokenUtil.CLAIMS_AUTH) == null) {
            throw new TokenCheckFailException(ExceptionMessage.NOT_AUTHORIZE_ACCESS);
        }

        // 클레임에서 권한 정보 가져오기
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(JwtTokenUtil.CLAIMS_AUTH).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // UserDetails 객체를 만들어서 Authentication 리턴
        UserDetails principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
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
     * Access Token 만료 기간 (발급 일 기준 하루) 을 리턴하는 메소드
     * @return 현재시간 + 1시간 Date 객체
     */
    private Date getAccessTokenExpiresIn() {
        long now = (new Date()).getTime();
        return new Date(now + JwtTokenUtil.ACCESS_TOKEN_EXPIRE_TIME);
    }

    /**
     * Refresh Token 만료 기간 (발급 일 기준 하루) 을 리턴하는 메소드
     * @return 현재시간 + 6시간 Date 객체
     */
    private Date getRefreshTokenExpiresIn() {
        long now = (new Date()).getTime();
        return new Date(now + JwtTokenUtil.REFRESH_TOKEN_EXPIRE_TIME);
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
