package org.entur.jwt.verifier;

/**
 * 
 * Exceptions assumed to be cause by client.
 * 
 */

public class JwtClientException extends JwtException {

	private static final long serialVersionUID = 1L;

	public JwtClientException() {
	}
	
    public JwtClientException(String message) {
        super(message);
    }

    public JwtClientException(String message, Throwable cause) {
        super(message, cause);
    }

    public JwtClientException(Throwable cause) {
        super(cause);
    }

}
