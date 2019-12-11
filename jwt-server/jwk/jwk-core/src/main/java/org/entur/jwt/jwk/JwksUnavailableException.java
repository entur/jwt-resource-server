package org.entur.jwt.jwk;

public class JwksUnavailableException extends JwksServiceException {

    private static final long serialVersionUID = 1L;

    public JwksUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }

    public JwksUnavailableException(String message) {
        super(message);
    }

    public JwksUnavailableException(Throwable cause) {
        super(cause);
    }

}
