package nerds.studiousTestProject.studycafe.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Map;

/**
 * DTO -> MultiValueMap Converter
 * DTO를 Query parameter에 추가하기 위해선 해당 Converter를 사용하여 DTO를 MultiValueMap 로 변환해야 한다.
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public abstract class MultiValueMapConverter {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static MultiValueMap<String, String> convert(Object dto) {
        try {
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            Map<String, String> map = objectMapper.convertValue(dto, new TypeReference<>() {});
            params.setAll(map);
            return params;
        } catch (Exception e) {
            log.error("msg = {}", e.getMessage());
            log.error("requestDto={}", dto, e);
            throw new IllegalStateException("Url Parameter 변환중 오류가 발생했습니다.");
        }
    }
}