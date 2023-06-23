package nerds.studiousTestProject.user.dto.oauth.userinfo;

import lombok.ToString;

import java.util.Map;

@ToString
public abstract class OAuth2UserInfo {
    protected Map<String, Object> attributes;
    protected OAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    public abstract String getProvider();

    // 이 때, 문자열은 값이 같으면 같은 해시코드 값을 갖고 있으므로 문자열을 해시코드로 변환한다.
    // 네이버의 경우 이 값이 문자열이므로 해시코드를 사용해야 한다.
    public abstract Long getProviderId();
    public abstract String getName();
    public abstract String getEmail();
}
