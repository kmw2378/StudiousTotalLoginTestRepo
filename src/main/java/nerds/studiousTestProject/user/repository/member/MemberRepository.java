package nerds.studiousTestProject.user.repository.member;

import nerds.studiousTestProject.user.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByEmail(String email);
    boolean existsByProviderId(Long providerId);
    boolean existsByEmail(String email);
}