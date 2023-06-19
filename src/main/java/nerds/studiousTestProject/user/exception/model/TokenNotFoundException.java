package nerds.studiousTestProject.user.exception.model;

import nerds.studiousTestProject.user.exception.message.ExceptionMessage;

public class TokenNotFoundException extends RuntimeException {
    public TokenNotFoundException(String message) {
        super(message);
    }

    public TokenNotFoundException(ExceptionMessage exceptionMessage) {
        super(exceptionMessage.message());
    }
}