package org.entur.jwt.client;

public class AccessTokenException extends Exception {

    private static final long serialVersionUID = 1L;

    public AccessTokenException() {
        super();
    }

    public AccessTokenException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public AccessTokenException(String message, Throwable cause) {
        super(message, cause);
    }

    public AccessTokenException(String message) {
        super(message);
    }

    public AccessTokenException(Throwable cause) {
        super(cause);
    }

}
