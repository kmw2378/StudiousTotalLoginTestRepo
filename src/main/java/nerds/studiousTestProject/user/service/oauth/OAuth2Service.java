package nerds.studiousTestProject.user.service.oauth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nerds.studiousTestProject.user.dto.general.token.JwtTokenResponse;
import nerds.studiousTestProject.user.dto.oauth.signup.OAuth2AuthenticateResponse;
import nerds.studiousTestProject.user.dto.oauth.token.OAuth2TokenRequest;
import nerds.studiousTestProject.user.dto.oauth.token.OAuth2TokenResponse;
import nerds.studiousTestProject.user.dto.oauth.userinfo.OAuth2UserInfo;
import nerds.studiousTestProject.user.dto.oauth.userinfo.OAuth2UserInfoFactory;
import nerds.studiousTestProject.user.entity.member.Member;
import nerds.studiousTestProject.user.entity.member.MemberType;
import nerds.studiousTestProject.user.exception.message.ExceptionMessage;
import nerds.studiousTestProject.user.exception.model.OAuth2Exception;
import nerds.studiousTestProject.user.service.member.MemberService;
import nerds.studiousTestProject.user.util.JwtTokenProvider;
import nerds.studiousTestProject.user.util.MultiValueMapConverter;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class OAuth2Service {
    private final InMemoryClientRegistrationRepository inMemoryClientRegistrationRepository;
    private final MemberService memberService;
    private final JwtTokenProvider jwtTokenProvider;
    private final WebClient webClient;

    /**
     * 소셜 인가 코드를 통해 소셜 서버로부터 토큰을 발급받는다.
     *  발급받은 토큰을 통해 로그인
     *  (만약, 회원 정보가 없는 경우 신규 등록)
     * @param providerName 소셜 이름 (google, naver, kakao) 중 하나
     * @param code 소셜 인가 코드
     * @return 소셜 서버로부터 발급받은 토큰을 통해 생성한 새로운 토큰
     */
    @Transactional
    public OAuth2AuthenticateResponse authenticate(String providerName, String code) {
        // application.properties (설정 파일)에 적어둔 정보들로 생성한 객체 중
        // registrationId 값이 현재 소셜 이름과 일치하는 객체를 가져온다.
        ClientRegistration provider = inMemoryClientRegistrationRepository.findByRegistrationId(providerName);
        log.info("provider = {}", provider.toString());

        // 소셜 서버로 부터 토큰 받아오기
        // 이는 실제 사용할 토큰이 아닌 유저 정보를 가져오기 위한 토큰 정보이다.
        OAuth2TokenResponse oAuth2TokenResponse = getSocialToken(code, provider);
        log.debug("token = {}", oAuth2TokenResponse.toString());

        // 소셜 엑세스 토큰을 통해 사용자 정보 받아오기
        Map<String, Object> attributes = getUserAttributes(provider, oAuth2TokenResponse);
        log.info("attributes = {}", attributes);

        // 팩토리 클래스를 통해 구글, 네이버, 카카오 중 알맞는 소셜 사용자 정보를 가져온다.
        OAuth2UserInfo oAuth2UserInfo = getOAuth2UserInfo(providerName, attributes);
        log.info("userInfo = {}", oAuth2UserInfo);

        // 응답 Body에 담을 객체 생성
        return getOAuth2AuthenticateResponse(oAuth2UserInfo);
    }

    /**
     * 소셜 이름(구글, 카카오, 네이버 중 하나) 와 유저 속성을 통해 알맞는 OAuth2User 객체를 반환하는 메소드
     * 팩토리 클래스 OAuth2UserInfoFactory 를 통해 소셜 이름에 알맞는 객체를 반환 (다형성 활용)
     * @param providerName 소셜 이름(구글, 카카오, 네이버 중 하나)
     * @param attributes 유저 속성
     * @return 소셜 이름에 알맞는 OAuth2User 객체
     */
    private OAuth2UserInfo getOAuth2UserInfo(String providerName, Map<String, Object> attributes) {
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getInstance(providerName, attributes);

        // 소셜 회원은 각각 고유의 소셜 Id 값(providerId)을 가진다. 이 값은 소셜 서버로부터 얻어온 사용자 정보에서 가져온다.
        // providerId == null 인 경우 (사용자 정보를 가져오지 못한 경우) 예외 발생
        Long providerId = oAuth2UserInfo.getProviderId();
        if (providerId == null) {
            throw new OAuth2Exception(ExceptionMessage.NOT_AUTHORIZE_ACCESS);
        }

        return oAuth2UserInfo;
    }

    /**
     * 소셜 서버로 부터 토큰 요청을 하는 메소드
     * @param code 프론트로부터 넘겨받은 인가 코드
     * @param provider 소셜에 알맞는 Provider (redirect_uri, token_uri 등..)
     * @return 소셜 서버로 부터 넘겨 받은 토큰 값들을 담은 객체
     */
    private OAuth2TokenResponse getSocialToken(String code, ClientRegistration provider) {
        return webClient
                    .post()
                    .uri(provider.getProviderDetails().getTokenUri())
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .bodyValue(getParams(code, provider))
                    .retrieve()
                    .bodyToMono(OAuth2TokenResponse.class)
                    .block();
    }

    /**
     * 소셜 서버로 토큰 발급 요청 시 Body에 넣은 값을 반환하는 메소드
     * @param code 프론트로부터 넘겨받은 인가코드
     * @param provider 소셜에 알맞는 Provider (redirect_uri, token_uri 등..)
     * @return 소셜 서버로 토큰 발급 요청 시 Body에 넣은 값을 담은 객체
     */
    private MultiValueMap<String, String> getParams(String code, ClientRegistration provider) {
        return MultiValueMapConverter.convert(
                OAuth2TokenRequest.builder()
                        .code(code)
                        .grant_type(provider.getAuthorizationGrantType().getValue())
                        .redirect_uri(provider.getRedirectUri())
                        .client_id(provider.getClientId())
                        .client_secret(provider.getClientSecret())
                        .build()
        );
    }

    /**
     * 소셜 서버로 부터 발급받은 토큰 값을 통해 해당 유저 속성을 반환하는 메소드
     * @param provider            소셜에 알맞는 Provider (redirect_uri, token_uri 등..)
     * @param oAuth2TokenResponse 소셜 서버로 부터 발급받은 토큰 값들이 저장된 DTO
     * @return 소셜 서버로 부터 발급받은 토큰의 유저 속성
     */
    private Map<String, Object> getUserAttributes(ClientRegistration provider, OAuth2TokenResponse oAuth2TokenResponse) {
        return webClient
                .get()
                .uri(provider.getProviderDetails().getUserInfoEndpoint().getUri())
                .headers(header -> header.setBearerAuth(oAuth2TokenResponse.getAccess_token()))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .block();
    }

    private OAuth2AuthenticateResponse getOAuth2AuthenticateResponse(OAuth2UserInfo oAuth2UserInfo) {
        // providerId를 통해 MemberRepository 확인
        Long providerId = oAuth2UserInfo.getProviderId();
        MemberType type = MemberType.valueOf(oAuth2UserInfo.getProvider());
        Optional<Member> memberOptional = memberService.findByProviderIdAndType(providerId, type);

        boolean exist = memberOptional.isPresent(); // 기존 회원인지 여부
        JwtTokenResponse jwtTokenResponse = null;
        OAuth2AuthenticateResponse.UserInfo userInfo = null;

        if (exist) {
            // 기존 회원인 경우 바로 로그인 메소드를 통해 토큰을 발급
            // 이때, AccessToken이 발급되며 RefreshToken은 응답 쿠키에 저장된다. (issueToken 메소드를 참고)
            jwtTokenResponse = jwtTokenProvider.generateToken(memberOptional.get());
        } else {
            // 신규 회원인 경우는 providerId, 소셜 타입, 이메일 정보를 저장
            // 추후, 이 값은 회원 가입 페이지로 넘어갈 때 사용된다.

            userInfo = OAuth2AuthenticateResponse.UserInfo.builder()
                    .providerId(providerId)
                    .email(oAuth2UserInfo.getEmail())
                    .type(type)
                    .build();
        }

        return OAuth2AuthenticateResponse
                .builder()
                .exist(exist)
                .jwtTokenResponse(jwtTokenResponse)
                .userInfo(userInfo)
                .build();
    }
}