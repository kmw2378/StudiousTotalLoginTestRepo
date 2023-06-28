package nerds.studiousTestProject.user.dto.general.login;

import lombok.Data;

@Data
public class MemberLoginRequest {
    private String email;
    private String password;
}
