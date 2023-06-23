package nerds.studiousTestProject.user.dto.oauth.userinfo;

import java.util.Map;

public class KakaoUserInfo extends OAuth2UserInfo {
    public KakaoUserInfo(Map<String, Object> attributes) {
        super(attributes);

    }
    @Override
    public String getProvider() {
        return "KAKAO";
    }

    @Override
    public Long getProviderId() {
        return (long) attributes.get("id").hashCode();
    }

    @Override
    public String getName() {
        return (String) parsingProfile().get("nickname");
    }

    @Override
    public String getEmail() {
        return parsingProperties().get("email") == null ? getProviderId() + "@kakao.com" : (String) parsingProperties().get("email");
    }

    private Map<String, Object> parsingProperties() {
        return (Map<String, Object>) attributes.get("kakao_account");
    }

    private Map<String, Object> parsingProfile() {
        return (Map<String, Object>) parsingProperties().get("profile");
    }
}
