package nerds.studiousTestProject.user.dto.general.find;

import lombok.Data;

@Data
public class FindPasswordRequest {
    private String email;
    private String phoneNumber;
}
