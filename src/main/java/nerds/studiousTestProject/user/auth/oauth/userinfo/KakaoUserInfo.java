package nerds.studiousTestProject.user.auth.oauth.userinfo;

import java.util.Map;

public class KakaoUserInfo extends OAuth2UserInfo {

    public KakaoUserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return String.valueOf(attributes.get("id"));
    }

    @Override
    public String getProvider() {
        return "kakao";
    }

    @Override
    public String getName() {
        return (String) parsingProfile().get("nickname");
    }

    @Override
    public String getEmail() {
        return (String) parsingProperties().get("email");
    }

    private Map<String, Object> parsingProperties() {
        return (Map<String, Object>) attributes.get("kakao_account");
    }

    private Map<String, Object> parsingProfile() {
        return (Map<String, Object>) parsingProperties().get("profile");
    }
}
