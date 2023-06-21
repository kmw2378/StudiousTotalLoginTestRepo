package nerds.studiousTestProject.user.dto.oauth.userinfo;

import java.util.Map;
import java.util.UUID;

public class GoogleUserInfo extends OAuth2UserInfo {

    public GoogleUserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return (String) attributes.get("id");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return attributes.get("email") == null ? UUID.randomUUID() + "@google.com" : (String) attributes.get("email");
    }
}
