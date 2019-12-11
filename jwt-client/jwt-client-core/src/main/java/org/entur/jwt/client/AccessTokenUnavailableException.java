package org.entur.jwt.client;

public class AccessTokenUnavailableException extends AccessTokenException {

    private static final long serialVersionUID = 1L;

    public AccessTokenUnavailableException() {
        super();
    }

    public AccessTokenUnavailableException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public AccessTokenUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }

    public AccessTokenUnavailableException(String message) {
        super(message);
    }

    public AccessTokenUnavailableException(Throwable cause) {
        super(cause);
    }

}
