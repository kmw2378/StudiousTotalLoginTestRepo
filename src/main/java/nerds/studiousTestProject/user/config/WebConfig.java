package nerds.studiousTestProject.user.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
//                .allowedOrigins("*")
                .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")   // 허용되는 Method
                .allowedOriginPatterns("*") // 외부에서 들어오는 모든 url 을 허용
                .allowedHeaders("*")    // 허용되는 헤더
                .exposedHeaders("*")    // response의 모든 헤더 허용
                .allowCredentials(true)    // 자격증명 허용
                .maxAge(3600);   // 허용 시간
    }
}