package nerds.studiousTestProject.user.exception.model;

import nerds.studiousTestProject.user.exception.message.ExceptionMessage;

public class OAuth2Exception extends RuntimeException {
    public OAuth2Exception(String message) {
        super(message);
    }

    public OAuth2Exception(ExceptionMessage exceptionMessage) {
        super(exceptionMessage.message());
    }
}
