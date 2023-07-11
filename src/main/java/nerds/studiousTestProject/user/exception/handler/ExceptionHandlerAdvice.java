package nerds.studiousTestProject.user.exception.handler;

import lombok.extern.slf4j.Slf4j;
import nerds.studiousTestProject.user.exception.dto.ExceptionDto;
import nerds.studiousTestProject.user.exception.model.OAuth2Exception;
import nerds.studiousTestProject.user.exception.model.TokenCheckFailException;
import nerds.studiousTestProject.user.exception.model.TokenNotFoundException;
import nerds.studiousTestProject.user.exception.model.UserAuthException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.reactive.function.client.WebClientResponseException;

@RestControllerAdvice
@Slf4j
public class ExceptionHandlerAdvice {
    @ExceptionHandler(value = {UserAuthException.class, OAuth2Exception.class, TokenNotFoundException.class, TokenCheckFailException.class})
    public ResponseEntity<ExceptionDto> userExceptionHandler(Exception e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ExceptionDto.builder()
                        .message(e.getMessage())
                        .statusCode(HttpStatus.BAD_REQUEST.value())
                        .build()
                );
    }

    @ExceptionHandler(value = HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ExceptionDto> methodNotSupportedExceptionHandler(Exception e) {
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                .body(ExceptionDto.builder()
                        .message(e.getMessage())
                        .statusCode(HttpStatus.METHOD_NOT_ALLOWED.value())
                        .build()
                );
    }

    @ExceptionHandler(value = WebClientResponseException.class)
    public ResponseEntity<ExceptionDto> webClientExceptionHandler(WebClientResponseException e) {
        log.error("msg = {}", e.getMessage());
        log.error("status = {}", e.getStatusText());
        log.error("body = {} ", e.getResponseBodyAsString());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ExceptionDto.builder()
                        .message("웹 API 호출 예외 발생. 자세한 건 서버 로그를 참고하세요.")
                        .statusCode(HttpStatus.INTERNAL_SERVER_ERROR.value())
                        .build()
                );
    }
}
