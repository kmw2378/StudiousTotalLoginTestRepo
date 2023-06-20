package nerds.studiousTestProject.user.service.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nerds.studiousTestProject.user.auth.oauth.userinfo.OAuth2UserInfo;
import nerds.studiousTestProject.user.auth.oauth.userinfo.OAuth2UserInfoFactory;
import nerds.studiousTestProject.user.dto.general.MemberType;
import nerds.studiousTestProject.user.dto.general.token.JwtTokenResponse;
import nerds.studiousTestProject.user.dto.oauth.KakaoTokenRequest;
import nerds.studiousTestProject.user.dto.oauth.KakaoTokenResponse;
import nerds.studiousTestProject.user.dto.oauth.OAuth2LogoutResponse;
import nerds.studiousTestProject.user.entity.Member;
import nerds.studiousTestProject.user.entity.oauth.OAuth2Token;
import nerds.studiousTestProject.user.entity.token.LogoutAccessToken;
import nerds.studiousTestProject.user.entity.token.RefreshToken;
import nerds.studiousTestProject.user.exception.message.ExceptionMessage;
import nerds.studiousTestProject.user.exception.model.UserAuthException;
import nerds.studiousTestProject.user.repository.member.MemberRepository;
import nerds.studiousTestProject.user.repository.oauth.OAuth2TokenRepository;
import nerds.studiousTestProject.user.service.token.LogoutAccessTokenService;
import nerds.studiousTestProject.user.service.token.RefreshTokenService;
import nerds.studiousTestProject.user.util.DateConverter;
import nerds.studiousTestProject.user.util.JwtTokenProvider;
import nerds.studiousTestProject.user.util.JwtTokenUtil;
import nerds.studiousTestProject.user.util.MultiValueMapConverter;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class OAuth2Service {
    private final OAuth2TokenRepository oAuth2TokenRepository;
    private final InMemoryClientRegistrationRepository inMemoryClientRegistrationRepository;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final LogoutAccessTokenService logoutAccessTokenService;
    private final RefreshTokenService refreshTokenService;
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    @Transactional
    public JwtTokenResponse authorize(String providerName, String code) {
        ClientRegistration provider = inMemoryClientRegistrationRepository.findByRegistrationId(providerName);
        log.info("provider = {}", provider.toString());

        // 토큰 받아오기
        // 이는 실제 사용할 토큰이 아닌 유저 정보를 가져오기 위한 토큰 정보이다.
        KakaoTokenResponse kakaoTokenResponse = getSocialToken(code, provider);
        log.debug("token = {}", kakaoTokenResponse.toString());

        // 소셜 엑세스 토큰을 통해 사용자 정보 받아오기
        Map<String, Object> attributes = getUserAttributes(provider, kakaoTokenResponse);
        log.info("attributes = {}", attributes);

        // 팩토리 클래스를 통해 구글, 네이버, 카카오 중 알맞는 소셜 사용자 정보를 가져온다.
        OAuth2UserInfo oAuth2UserInfo = getOAuth2UserInfo(providerName, attributes);
        log.info("userInfo = {}", oAuth2UserInfo.toString());

        // 유저 정보를 통해 이메일, 비밀번호 생성 (이 때, 비밀번호는 UUID 를 통해 랜덤으로 생성)
        String email = oAuth2UserInfo.getEmail();
        String password = UUID.randomUUID().toString();

        // 토큰을 만들기 전 Repository 에 있는지 여부를 확인 후 이를 완료하고 진행하자.
        // 별도로 DB를 두지 말고 Member 로 통합해도 괜찮을 것 같음 (컬럼만 추가하자)
        if (memberRepository.existsByEmail(email)) {
            throw new UserAuthException(ExceptionMessage.ALREADY_EXIST_USER);
        }

        String encode = passwordEncoder.encode(password);
        List<String> roles = Collections.singletonList("USER");
        Member member = Member.builder()
                .email(email)
                .password(encode)
                .roles(roles)
                .type(MemberType.OAUTH)
                .build();
        if (memberRepository.existsByEmail(email)) {
            memberRepository.save(member);
        }

        // 기존 소셜 토큰 정보를 DB에 저장 (추후 로그아웃을 위해)
        oAuth2TokenRepository.save(
                OAuth2Token.builder()
                .email(email)
                .accessToken(kakaoTokenResponse.getAccess_token())
                .refreshToken(kakaoTokenResponse.getRefresh_token())
                .expiredAt(DateConverter.toLocalDateTime(kakaoTokenResponse.getExpires_in()))
                .build()
        );

        Authentication authentication = getAuthentication(email, password); // 이메일, 비밀번호를 통해 인증 정보 생성

        // 만든 이메일, 비밀번호와 소셜 서버로부터 받아온 만료 기간을 통해 토큰 생성
        String accessToken = jwtTokenProvider.createAccessToken(authentication);

        // Refresh 토큰 저장소에 만든 Refresh 토큰 저장
        RefreshToken refreshToken = refreshTokenService.saveRefreshToken(email);
        jwtTokenProvider.setRefreshTokenAtCookie(refreshToken);

        return JwtTokenResponse.from(accessToken);
    }

    public void logout(String providerName, String accessToken) {
        String resolvedAccessToken = jwtTokenProvider.resolveToken(accessToken);
        String email = jwtTokenProvider.parseToken(resolvedAccessToken);

        Optional<OAuth2Token> oAuth2TokenOptional = oAuth2TokenRepository.findByEmail(email);
        if (oAuth2TokenOptional.isEmpty()) {
            throw new RuntimeException("올바르지 않은 소셜 정보 입니다.");
        }
        OAuth2Token oAuth2Token = oAuth2TokenOptional.get();

        ClientRegistration provider = inMemoryClientRegistrationRepository.findByRegistrationId(providerName);
        OAuth2LogoutResponse oAuth2LogoutResponse = null;
        try {
            oAuth2LogoutResponse = WebClient.create()
                    .post()
                    .uri("https://kapi.kakao.com/v1/user/logout")
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .header(HttpHeaders.AUTHORIZATION, JwtTokenUtil.TOKEN_PREFIX + " " + oAuth2Token.getAccessToken())
                    .retrieve()
                    .bodyToMono(OAuth2LogoutResponse.class)
                    .block();
        } catch (WebClientResponseException e) {
            log.error("msg = {}", e.getMessage());
            log.error("status = {}", e.getStatusCode());
            log.error("body = {}", e.getResponseBodyAsString());
        }

        Long remainTime = jwtTokenProvider.getRemainTime(resolvedAccessToken);
        refreshTokenService.deleteRefreshTokenByEmail(email);

        logoutAccessTokenService.saveLogoutAccessToken(LogoutAccessToken.from(email, resolvedAccessToken, remainTime));
    }

    private OAuth2UserInfo getOAuth2UserInfo(String providerName, Map<String, Object> attributes) {
        OAuth2UserInfo oAuth2UserInfo;
        try {
           oAuth2UserInfo  = OAuth2UserInfoFactory.getOAuth2UserInfo(providerName, attributes);
        } catch (IllegalArgumentException e) {
            log.error("providerName = {}", providerName);
            log.error("attributes = {}", attributes);
            throw new RuntimeException("알맞는 소셜 서비스를 찾을 수 없습니다.");
        }

        return oAuth2UserInfo;
    }

    private KakaoTokenResponse getSocialToken(String code, ClientRegistration provider) {
        KakaoTokenResponse kakaoTokenResponse = null;
        try {
            kakaoTokenResponse = WebClient.create()
                    .post()
                    .uri(provider.getProviderDetails().getTokenUri())
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .bodyValue(getParams(code, provider))
                    .retrieve()
                    .bodyToMono(KakaoTokenResponse.class)
                    .block();
        } catch (WebClientResponseException e) {
            log.error("msg = {}", e.getMessage());
            log.error("status = {}", e.getStatusText());
            log.error("body = {}", e.getResponseBodyAsString());
        }

        return kakaoTokenResponse;
    }

    private MultiValueMap<String, String> getParams(String code, ClientRegistration provider) {
        return MultiValueMapConverter.convert(
                new ObjectMapper(),
                KakaoTokenRequest.builder()
                        .code(code)
                        .grant_type("authorization_code")
                        .redirect_uri(provider.getRedirectUri())
                        .client_id(provider.getClientId())
                        .build()
        );
    }

    private Map<String, Object> getUserAttributes(ClientRegistration provider, KakaoTokenResponse kakaoTokenResponse) {
        return WebClient.create()
                .get()
                .uri(provider.getProviderDetails().getUserInfoEndpoint().getUri())
                .headers(header -> header.setBearerAuth(kakaoTokenResponse.getAccess_token()))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .block();
    }

    private Authentication getAuthentication(String email, String password) {
        // 1. 아이디/비밀번호를 기반으로 Authentication 객체 생성
        // 이 때, authentication 는 인증 여부를 확인하는 authenticated 값이 false
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(email, password);

        // 2. 실제 검증(사용자 비밀번호 체크) 이 실행되는 부분
        // authenticate 메소드가 실행 될 때 MemberService 에서 loadUserByUsername 메소드가 실행된다.
        return authenticationManagerBuilder.getObject().authenticate(authenticationToken);
    }
}