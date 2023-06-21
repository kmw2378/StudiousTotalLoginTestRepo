package nerds.studiousTestProject.user.dto.oauth.userinfo;

import java.util.Map;

public class DefaultUserInfo extends OAuth2UserInfo {

    public DefaultUserInfo(Map<String, Object> attributes) {
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
        return (String) attributes.get("email");
    }
}
