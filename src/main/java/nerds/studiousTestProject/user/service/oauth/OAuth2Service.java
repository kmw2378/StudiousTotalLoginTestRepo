package nerds.studiousTestProject.user.service.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nerds.studiousTestProject.user.auth.oauth.OAuth2Token;
import nerds.studiousTestProject.user.auth.oauth.account.OAuth2Account;
import nerds.studiousTestProject.user.auth.oauth.account.OAuth2AccountRepository;
import nerds.studiousTestProject.user.auth.oauth.userinfo.OAuth2UserInfo;
import nerds.studiousTestProject.user.auth.oauth.userinfo.OAuth2UserInfoFactory;
import nerds.studiousTestProject.user.dto.general.MemberType;
import nerds.studiousTestProject.user.dto.general.token.JwtTokenResponse;
import nerds.studiousTestProject.user.dto.oauth.token.kakao.KakaoTokenRequest;
import nerds.studiousTestProject.user.dto.oauth.token.kakao.KakaoTokenResponse;
import nerds.studiousTestProject.user.entity.Member;
import nerds.studiousTestProject.user.repository.member.MemberRepository;
import nerds.studiousTestProject.user.service.token.RefreshTokenService;
import nerds.studiousTestProject.user.util.DateConverter;
import nerds.studiousTestProject.user.util.JwtTokenProvider;
import nerds.studiousTestProject.user.util.MultiValueMapConverter;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class OAuth2Service {
    private final OAuth2AccountRepository oAuth2AccountRepository;
    private final InMemoryClientRegistrationRepository inMemoryClientRegistrationRepository;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final MemberRepository memberRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;

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

        // 팩토리 클래스를 통해 구글, 네이버, 카카오 중 알맞는 소셜 사용자 정보를 가져온다.
        OAuth2UserInfo oAuth2UserInfo = getOAuth2UserInfo(providerName, attributes);

        // 유저 정보를 통해 이메일, 비밀번호 생성 (이 때, 비밀번호는 UUID 를 통해 랜덤으로 생성)
        String email = oAuth2UserInfo.getEmail();
        String password = UUID.randomUUID().toString();
        Authentication authentication = getAuthentication(email, password); // 이메일, 비밀번호를 통해 인증 정보 생성

        // 만든 이메일, 비밀번호와 소셜 서버로부터 받아온 만료 기간을 통해 토큰 생성
        OAuth2Token oAuth2Token = OAuth2Token.builder()
                .token(jwtTokenProvider.createAccessToken(authentication))
                .refreshToken(jwtTokenProvider.createRefreshToken())
                .expiredAt(DateConverter.toLocalDateTime(kakaoTokenResponse.getExpires_in()))
                .build();

//        Long refreshTokenExpiresIn = kakaoTokenResponse.getRefresh_token_expires_in(); 이거도 써야되는디,,,

        // 가져온 소셜 사용자 정보가 기존 DB에 있는지 조회
        // 만약 없다면 새롭게 만들고, 있다면 연관관계 생성
        saveMemberProfile(oAuth2Token, oAuth2UserInfo);

        // Refresh 토큰 저장소에 만든 Refresh 토큰 저장
        refreshTokenService.saveRefreshTokenFromOAuth2(oAuth2Token, oAuth2UserInfo);

        return JwtTokenResponse.builder()
                .grantType(kakaoTokenResponse.getToken_type())
                .accessToken(oAuth2Token.getToken())
                .build();
    }

    private  OAuth2UserInfo getOAuth2UserInfo(String providerName, Map<String, Object> attributes) {
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

    private void saveMemberProfile(OAuth2Token oAuth2Token, OAuth2UserInfo oAuth2UserInfo) {
        String provide = oAuth2UserInfo.getProvider();
        String id = oAuth2UserInfo.getId();
        String email = oAuth2UserInfo.getEmail();
//        String name = oAuth2UserInfo.getName();

        Optional<OAuth2Account> oAuth2AccountOptional = oAuth2AccountRepository.findByProviderAndProviderId(provide, id);
        Member member;
        // 가입된 계정이 존재할때
        if (oAuth2AccountOptional.isPresent()) {
            OAuth2Account oAuth2Account = oAuth2AccountOptional.get();
            member = oAuth2Account.getMember();
            // 토큰 업데이트
            oAuth2Account.updateToken(
                    oAuth2Token.getToken(),
                    oAuth2Token.getRefreshToken(),
                    oAuth2Token.getExpiredAt());
        }
        // 가입된 계정이 존재하지 않을때
        else {
            // DB에 저장할 소셜 계정 정보 생성
            OAuth2Account newAccount = OAuth2Account.builder()
                    .provider(oAuth2UserInfo.getProvider())
                    .providerId(oAuth2UserInfo.getId())
                    .token(oAuth2Token.getToken())
                    .refreshToken(oAuth2Token.getRefreshToken())
                    .tokenExpiredAt(oAuth2Token.getExpiredAt())
                    .build();
            oAuth2AccountRepository.save(newAccount);

            // 이메일 정보가 있을때
            if (email != null) {
                // 같은 이메일을 사용하는 계정이 존재하는지 확인 후 있다면 소셜 계정과 연결시키고 없다면 새로 생성한다
                member = memberRepository.findByEmail(email)
                        .orElse(Member.builder()
                                .email(email)
                                .roles(Collections.singletonList("USER"))
                                .type(MemberType.OAUTH)
                                .build());
            }
            // 이메일 정보가 없을때
            else {
                member = Member.builder()
                        .roles(Collections.singletonList("USER"))
                        .type(MemberType.OAUTH)
                        .build();
            }

            // 새로 생성된 유저이면 db에 저장
            if (member.getEmail() == null)
                memberRepository.save(member);

            // 연관관계 설정
            member.linkSocial(newAccount);
        }
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
