package nerds.studiousTestProject.user.repository.member;

import nerds.studiousTestProject.user.entity.member.Member;
import nerds.studiousTestProject.user.entity.member.MemberType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByEmail(String email);
    Optional<Member> findByProviderId(Long providerId);
    Optional<Member> findByPhoneNumber(String PhoneNumber);
    boolean existsByPhoneNumber(String phoneNumber);
}