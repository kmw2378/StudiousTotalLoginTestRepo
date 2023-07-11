package nerds.studiousTestProject.user.dto.general.patch;

import lombok.Data;

@Data
public class PatchPasswordRequest {
    private String oldPassword;
    private String newPassword;
}
