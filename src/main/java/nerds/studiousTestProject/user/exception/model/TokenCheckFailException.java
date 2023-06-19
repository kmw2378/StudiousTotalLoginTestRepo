package nerds.studiousTestProject.user.exception.model;

import nerds.studiousTestProject.user.exception.message.ExceptionMessage;

public class TokenCheckFailException extends RuntimeException {
    public TokenCheckFailException(String message) {
        super(message);
    }

    public TokenCheckFailException(ExceptionMessage exceptionMessage) {
        super(exceptionMessage.message());
    }
}