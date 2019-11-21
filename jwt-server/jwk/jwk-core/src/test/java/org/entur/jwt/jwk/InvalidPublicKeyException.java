package org.entur.jwt.jwk;

public class InvalidPublicKeyException extends JwksServiceException {

	private static final long serialVersionUID = 1L;

	public InvalidPublicKeyException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
