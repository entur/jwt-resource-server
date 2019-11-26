package org.entur.jwt.jwk;

public class InvalidSigningKeysException extends JwksServiceException {

	private static final long serialVersionUID = 1L;

	public InvalidSigningKeysException(String message) {
		super(message);
	}

	public InvalidSigningKeysException(String message, Throwable cause) {
		super(message, cause);
	}
}
