package nerds.studiousTestProject.user.exception.model;

import nerds.studiousTestProject.user.exception.message.ExceptionMessage;

public class UserAuthException extends RuntimeException {
    public UserAuthException(String message) {
        super(message);
    }

    public UserAuthException(ExceptionMessage exceptionMessage) {
        super(exceptionMessage.message());
    }
}
