package nerds.studiousTestProject.user.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/*
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOriginPatterns(
                        "http://localhost:8080",
                        "http://ec2-54-180-201-100.ap-northeast-2.compute.amazonaws.com:8080",
                        "http://localhost:3000"
                )
                .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE")   // 허용되는 Method
                .allowedHeaders("*")    // 허용되는 헤더
                .exposedHeaders("*")    // response의 모든 헤더 허용
                .allowCredentials(true)    // 자격증명 허용
                .maxAge(3600);   // 허용 시간
    }
}
 */