package nerds.studiousTestProject.user.dto.general;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import nerds.studiousTestProject.user.util.DateConverter;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
public class MemberProfileResponse {

    private Long id;
    private String nickname;
    private String email;
    private List<String> authorities;
    private String socialProvider;
    private Long linkedAt;

    @Builder
    public MemberProfileResponse(Long id, String nickname, String email, List<String> authorities, String socialProvider, LocalDateTime linkedAt) {
        this.id = id;
        this.nickname = nickname;
        this.email = email;
        this.authorities = authorities;
        this.socialProvider = socialProvider;
        if (linkedAt != null) {
            this.linkedAt = DateConverter.toEpochMilli(linkedAt);
        }
    }
}
