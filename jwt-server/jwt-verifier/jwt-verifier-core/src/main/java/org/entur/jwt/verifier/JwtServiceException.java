package org.entur.jwt.verifier;

/**
 * 
 * Exceptions assumed to be cause by server.
 * 
 */

public class JwtServiceException extends JwtException {

	private static final long serialVersionUID = 1L;

	public JwtServiceException() {
	}
	
    public JwtServiceException(String message) {
        super(message);
    }

    public JwtServiceException(String message, Throwable cause) {
        super(message, cause);
    }

    public JwtServiceException(Throwable cause) {
        super(cause);
    }

}
