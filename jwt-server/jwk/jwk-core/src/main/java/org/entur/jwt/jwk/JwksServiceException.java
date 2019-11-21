package org.entur.jwt.jwk;

/**
 * 
 * Exceptions assumed to be caused by server.
 * 
 */

public class JwksServiceException extends JwksException {

	private static final long serialVersionUID = 1L;

    public JwksServiceException(String message) {
        super(message);
    }

    public JwksServiceException(String message, Throwable cause) {
        super(message, cause);
    }

    public JwksServiceException(Throwable cause) {
        super(cause);
    }

}
