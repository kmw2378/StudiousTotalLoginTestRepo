package nerds.studiousTestProject.user.config;

import lombok.RequiredArgsConstructor;
import nerds.studiousTestProject.user.jwt.filter.JwtAuthenticationFilter;
import nerds.studiousTestProject.user.util.JwtTokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Spring Security 관련 설정 사항들
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtTokenProvider jwtTokenProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.httpBasic().disable()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeHttpRequests()
                .requestMatchers(CorsUtils::isPreFlightRequest).permitAll() // Preflight request에 대해, 인증을 하지 않고 모든 요청을 허용
                .requestMatchers("/studious/members/signup", "/studious/members/login",  "/studious/oauth/authenticate/**").permitAll()    // 일반, 소셜 회원가입 및 로그인
                .requestMatchers("/studious/members/logout", "/studious/members/reissue").hasAnyRole("USER", "ADMIN", "SUPER_ADMIN")  // 로그아웃, 토큰 재발급
                .requestMatchers("/studious/mypage/**").hasAnyRole("USER", "ADMIN", "SUPER_ADMIN") // 닉네임, 비밀번호 수정 및 회원 탈퇴
                .requestMatchers(HttpMethod.GET, "/studious/members/email").permitAll()      // 이메일 찾기
                .requestMatchers(HttpMethod.POST, "/studious/members/password").permitAll()  // 비밀번호 찾기
                .requestMatchers("/studious/members/test").hasRole("USER")      // 테스트 용
                .anyRequest().authenticated()
                .and()
                .cors()
                .and()
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    //Cors 설정
    // Spring MVC 보다 Spring Security가 먼저 실행되므로 Cors 설정은 Security 에서 하는 것이 좋다.
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.addAllowedOriginPattern("*");
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");
//        configuration.addExposedHeader("*"); 노출할 헤더들
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public WebClient webClient() {
        return WebClient.create();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
