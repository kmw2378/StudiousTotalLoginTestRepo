package nerds.studiousTestProject.user.dto.general.logout;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LogoutResponse {
    Long memberId;
}
