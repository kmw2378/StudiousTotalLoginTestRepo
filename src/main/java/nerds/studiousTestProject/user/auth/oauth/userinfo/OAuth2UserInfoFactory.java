package nerds.studiousTestProject.user.auth.oauth.userinfo;

import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String providerName, Map<String, Object> attributes) {
        return switch (providerName.toLowerCase()) {
            case "google" -> new GoogleUserInfo(attributes);
            case "naver" -> new NaverUserInfo(attributes);
            case "kakao" -> new KakaoUserInfo(attributes);
            default -> throw new IllegalArgumentException(providerName.toUpperCase() + " 로그인은 지원하지 않습니다.");
        };
    }
}
