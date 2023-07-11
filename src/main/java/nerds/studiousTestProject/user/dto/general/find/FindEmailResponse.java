package nerds.studiousTestProject.user.dto.general.find;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class FindEmailResponse {
    private String email;
}