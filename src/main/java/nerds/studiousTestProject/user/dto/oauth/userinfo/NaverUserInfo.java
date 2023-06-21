package nerds.studiousTestProject.user.dto.oauth.userinfo;

import java.util.Map;

public class NaverUserInfo extends OAuth2UserInfo {

    public NaverUserInfo(Map<String, Object> attributes) {
        super(attributes);
    }
    @Override
    public String getId() {
        return (String) parsingProperties().get("id");
    }

    @Override
    public String getName() {
        return (String) parsingProperties().get("name");
    }

    @Override
    public String getEmail() {
        return (String) parsingProperties().get("email");
    }

    private Map<String, Object> parsingProperties() {
        return (Map<String, Object>) attributes.get("response");
    }
}
