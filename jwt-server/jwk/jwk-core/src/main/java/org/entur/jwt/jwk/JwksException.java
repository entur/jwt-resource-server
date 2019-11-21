package org.entur.jwt.jwk;

/**
 * Top-level Json Web Keys exception.
 * 
 */

public class JwksException extends Exception {

	private static final long serialVersionUID = 1L;

	public JwksException() {
	}
	
    public JwksException(String message) {
        super(message);
    }

    public JwksException(String message, Throwable cause) {
        super(message, cause);
    }

    public JwksException(Throwable cause) {
        super(cause);
    }

}
