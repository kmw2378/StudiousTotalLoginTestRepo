package nerds.studiousTestProject.user.dto.oauth.userinfo;

import lombok.ToString;

import java.util.Map;

@ToString
public abstract class OAuth2UserInfo {
    protected Map<String, Object> attributes;
    protected OAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }
    public abstract String getProviderId();
    public abstract String getName();
    public abstract String getEmail();
}
