package nerds.studiousTestProject.user.dto.oauth.userinfo;

import java.util.Map;
import java.util.UUID;

public class GoogleUserInfo extends OAuth2UserInfo {

    public GoogleUserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getProvider() {
        return "GOOGLE";
    }

    @Override
    public Long getProviderId() {
        return (long) attributes.get("id").hashCode();
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
