package nerds.studiousTestProject.user.service.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nerds.studiousTestProject.user.auth.oauth.account.OAuth2Account;
import nerds.studiousTestProject.user.auth.oauth.account.OAuth2AccountRepository;
import nerds.studiousTestProject.user.auth.oauth.userinfo.OAuth2UserInfo;
import nerds.studiousTestProject.user.auth.oauth.userinfo.OAuth2UserInfoFactory;
import nerds.studiousTestProject.user.dto.general.MemberType;
import nerds.studiousTestProject.user.dto.oauth.token.TokenInfo;
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
    public TokenInfo authorize(String providerName, String code) {
        ClientRegistration provider = inMemoryClientRegistrationRepository.findByRegistrationId(providerName);
        KakaoTokenResponse kakaoTokenResponse = getToken(code, provider);
        Member member = getMemberProfile(providerName, kakaoTokenResponse, provider);

        Authentication authentication = getAuthentication(member.getEmail(), kakaoTokenResponse.getAccess_token());
        String accessToken = jwtTokenProvider.createAccessToken(authentication);

        refreshTokenService.saveRefreshToken(member.getEmail());

        return TokenInfo.builder()
                .grantType(kakaoTokenResponse.getToken_type())
                .accessToken(accessToken)
                .build();
    }

    private KakaoTokenResponse getToken(String code, ClientRegistration provider) {
        KakaoTokenResponse kakaoTokenResponse = null;
        try {
            kakaoTokenResponse = WebClient.create()
                    .post()
                    .uri(provider.getProviderDetails().getTokenUri())
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .bodyValue(tokenRequest(code, provider))
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

    private MultiValueMap<String, String> tokenRequest(String code, ClientRegistration provider) {
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

    private Member getMemberProfile(String providerName, KakaoTokenResponse kakaoTokenResponse, ClientRegistration provider) {
        Map<String, Object> userAttributes = getUserAttributes(provider, kakaoTokenResponse);
        OAuth2UserInfo oAuth2UserInfo = null;
        try {
            oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(providerName, userAttributes);
        } catch (IllegalArgumentException e) {
            log.error("msg = {}", e.getMessage());
        }

        String provide = oAuth2UserInfo.getProvider();
        String id = oAuth2UserInfo.getId();
        String email = oAuth2UserInfo.getEmail();
        String name = oAuth2UserInfo.getName();

        Optional<OAuth2Account> oAuth2AccountOptional = oAuth2AccountRepository.findByProviderAndProviderId(provide, id);
        Member member;
        //가입된 계정이 존재할때
        if (oAuth2AccountOptional.isPresent()) {
            OAuth2Account oAuth2Account = oAuth2AccountOptional.get();
            member = oAuth2Account.getMember();
            //토큰 업데이트
            oAuth2Account.updateToken(kakaoTokenResponse.getRefresh_token(), kakaoTokenResponse.getRefresh_token(), DateConverter.toLocalDateTime(kakaoTokenResponse.getExpires_in()));
        }
        //가입된 계정이 존재하지 않을때
        else {
            //소셜 계정 정보 생성
            OAuth2Account newAccount = OAuth2Account.builder()
                    .provider(oAuth2UserInfo.getProvider())
                    .providerId(oAuth2UserInfo.getId())
                    .token(kakaoTokenResponse.getAccess_token())
                    .refreshToken(kakaoTokenResponse.getRefresh_token())
                    .tokenExpiredAt(DateConverter.toLocalDateTime(kakaoTokenResponse.getExpires_in())).build();
            oAuth2AccountRepository.save(newAccount);

            //이메일 정보가 있을때
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

            //새로 생성된 유저이면 db에 저장
            if (member.getEmail() == null)
                memberRepository.save(member);

            //연관관계 설정
            member.linkSocial(newAccount);
        }

        return member;
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
