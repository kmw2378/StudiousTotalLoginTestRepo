package nerds.studiousTestProject.user.dto.general.signup;

import lombok.Builder;
import lombok.Data;
import nerds.studiousTestProject.user.entity.member.MemberType;

import java.util.Date;
import java.util.List;

@Data
@Builder
public class SignUpRequest {
    private String email;
    private String password;
    private String name;
    private String nickname;
    private Long providerId;
    private MemberType type;
    private Date birthday;
    private String phoneNumber;
    private List<String> roles;
}
