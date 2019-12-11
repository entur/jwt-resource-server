package org.entur.jwt.client;

public class AccessTokenProviderBuilderException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public AccessTokenProviderBuilderException() {
        super();
    }

    public AccessTokenProviderBuilderException(String message, Throwable cause) {
        super(message, cause);
    }

    public AccessTokenProviderBuilderException(String message) {
        super(message);
    }

    public AccessTokenProviderBuilderException(Throwable cause) {
        super(cause);
    }

}
