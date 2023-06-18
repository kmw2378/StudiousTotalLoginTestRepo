package nerds.studiousTestProject.user.dto.oauth.constant;

public class KakaoLoginConstant {
    public final static String LOGIN_URI = "https://kauth.kakao.com/oauth/authorize";
    public final static String GRANT_TYPE = "authorization_code";
    public final static String REDIRECT_URI = "http://ec2-54-180-201-100.ap-northeast-2.compute.amazonaws.com:8080/get-token";
    public final static String TOKEN_URI = "https://kauth.kakao.com/oauth/token";
    public final static String REST_API = "840802008a58093510f5294d2e7c67c9";
}
