package org.entur.jwt.client;

public class RefreshTokenException extends AccessTokenException {

    private static final long serialVersionUID = 1L;

    public RefreshTokenException() {
        super();
    }

    public RefreshTokenException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public RefreshTokenException(String message, Throwable cause) {
        super(message, cause);
    }

    public RefreshTokenException(String message) {
        super(message);
    }

    public RefreshTokenException(Throwable cause) {
        super(cause);
    }

}
