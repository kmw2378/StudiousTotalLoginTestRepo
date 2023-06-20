package nerds.studiousTestProject.user.repository.member;

import nerds.studiousTestProject.user.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, String> {
    Optional<Member> findByEmail(String email);
    boolean existsByEmail(String email);
}