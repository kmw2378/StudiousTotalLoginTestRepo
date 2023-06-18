package nerds.studiousTestProject.user.dto.general;

import lombok.Data;

@Data
public class MemberLoginRequest {
    private String email;
    private String password;
}
