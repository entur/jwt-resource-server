package org.entur.jwt.client;

public class AccessTokenHealthNotSupportedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public AccessTokenHealthNotSupportedException() {
        super();
    }

    public AccessTokenHealthNotSupportedException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public AccessTokenHealthNotSupportedException(String message, Throwable cause) {
        super(message, cause);
    }

    public AccessTokenHealthNotSupportedException(String message) {
        super(message);
    }

    public AccessTokenHealthNotSupportedException(Throwable cause) {
        super(cause);
    }

}
