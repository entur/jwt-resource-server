package org.entur.jwt.jwk;

/**
 * 
 * Exceptions assumed to be caused by client.
 * 
 */

public class JwksClientException extends JwksException {

	private static final long serialVersionUID = 1L;

	public JwksClientException() {
	}

	public JwksClientException(String message) {
		super(message);
	}

	public JwksClientException(String message, Throwable cause) {
		super(message, cause);
	}


}
