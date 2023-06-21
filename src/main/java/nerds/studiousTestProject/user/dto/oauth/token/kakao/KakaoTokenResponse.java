package nerds.studiousTestProject.user.dto.oauth.token.kakao;

import lombok.Data;

/**
 * 카카오 로그인 서버로부터 토큰 발급 시 응답 DTO
 */
@Data
public class KakaoTokenResponse {
    private String token_type;  // 토큰 타입, bearer로 고정
    private String access_token; // 사용자 액세스 토큰 값
    private Long expires_in;    // 액세스 토큰과 ID 토큰의 만료 시간(초)
    private String refresh_token;   // 사용자 리프레시 토큰 값
    private Long refresh_token_expires_in;  // 리프레시 토큰 만료 시간(초)
    private String scope;   // 인증된 사용자의 정보 조회 권한 범위. 범위가 여러 개일 경우, 공백으로 구분
}
