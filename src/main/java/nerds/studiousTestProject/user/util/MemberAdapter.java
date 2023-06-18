package nerds.studiousTestProject.user.util;

import lombok.Getter;
import nerds.studiousTestProject.user.entity.Member;
import org.springframework.security.core.userdetails.User;

@Getter
public class MemberAdapter extends User {
    private Member member;

    public MemberAdapter(Member member) {
        super(member.getEmail(), member.getPassword(), member.getAuthorities());
        this.member = member;
    }
}
