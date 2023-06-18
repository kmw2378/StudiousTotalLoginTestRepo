package nerds.studiousTestProject.user.dto.general;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@Builder
public class MemberSignUpResponse {
    private String email;
    private String password;
    private List<String> roles;
}
