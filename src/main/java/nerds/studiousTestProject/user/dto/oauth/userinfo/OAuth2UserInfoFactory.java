package nerds.studiousTestProject.user.dto.oauth.userinfo;

import java.util.Map;

public class OAuth2UserInfoFactory {
    public static OAuth2UserInfo getInstance(String registrationId, Map<String, Object> attributes) {
        return switch (registrationId.toLowerCase()) {
            case "google" -> new GoogleUserInfo(attributes);
            case "naver" -> new NaverUserInfo(attributes);
            case "kakao" -> new KakaoUserInfo(attributes);
            default -> throw new IllegalArgumentException(registrationId.toUpperCase() + " 로그인은 지원하지 않습니다.");
        };
    }
}
