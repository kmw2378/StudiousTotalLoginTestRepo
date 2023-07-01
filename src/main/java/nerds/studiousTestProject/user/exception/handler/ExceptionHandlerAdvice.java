package nerds.studiousTestProject.user.exception.handler;

import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import nerds.studiousTestProject.user.exception.dto.ExceptionDto;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@Slf4j
public class ExceptionHandlerAdvice {
    @ExceptionHandler(value = Exception.class)
    public ResponseEntity<ExceptionDto> exceptionHandler(Exception exception, HttpServletResponse response) {
        return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE)
                .body(ExceptionDto.builder()
                        .message(String.format("%s", exception.getMessage()))
                        .statusCode(response.getStatus())
                        .build()
                );
    }
}
