package nerds.studiousTestProject.user.service.member;

import lombok.RequiredArgsConstructor;
import nerds.studiousTestProject.user.entity.member.Member;
import nerds.studiousTestProject.user.entity.member.MemberType;
import nerds.studiousTestProject.user.exception.message.ExceptionMessage;
import nerds.studiousTestProject.user.repository.member.MemberRepository;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class CustomerUserDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;

    /**
     * memberId를 사용하여 UserDetailsService 구현
     * @param username the username identifying the user whose data is required.
     * @return 현재 사용자의 정보
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, NumberFormatException {
        return memberRepository.findById(Long.valueOf(username))
                .map(this::createUserDetails)
                .orElseThrow(() -> new UsernameNotFoundException(ExceptionMessage.USER_NOT_FOUND.message()));
    }

    private UserDetails createUserDetails(Member member) {
        return User.builder()
                .username(member.getUsername())
                .password(member.getPassword())
                .roles(member.getRoles().toArray(new String[0]))
                .build();
    }
}