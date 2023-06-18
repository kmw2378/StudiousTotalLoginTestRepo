package nerds.studiousTestProject.user.config;

import lombok.RequiredArgsConstructor;
import nerds.studiousTestProject.user.jwt.filter.JwtAuthenticationFilter;
import nerds.studiousTestProject.user.util.JwtTokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
                .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                .requestMatchers("/*/signup/*").permitAll()
                .requestMatchers("/*/login/*", "/members/logout").hasAnyRole("USER", "ADMIN", "SUPER_ADMIN")
                .requestMatchers("/members/test").hasRole("USER")
                .requestMatchers("/members/reissue").hasRole("USER")
//                .requestMatchers("/oauth/**").hasAnyRole("USER", "ADMIN", "SUPER_ADMIN")
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.addAllowedOrigin("http://localhost:3000"); // 프론트 로컬
        config.addAllowedOrigin("http://localhost:8080"); // 백엔드 로컬
        config.addAllowedOrigin("http://ec2-54-180-201-100.ap-northeast-2.compute.amazonaws.com:8080"); // 백엔드 IPv4 주소
//        config.addAllowedOrigin("http://프론트 AWS  주소"); // 프론트 IPv4 주소
        config.addAllowedMethod("*");   // 모든 메소드 허용.
        config.addAllowedHeader("*");   // 모든 헤더 허용

        config.setAllowCredentials(true);   // 쿠키 허용

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
