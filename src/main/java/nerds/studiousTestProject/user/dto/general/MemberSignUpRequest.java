package nerds.studiousTestProject.user.dto.general;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
public class MemberSignUpRequest {
    private String email;
    private String password;
    private List<String> roles;
}
