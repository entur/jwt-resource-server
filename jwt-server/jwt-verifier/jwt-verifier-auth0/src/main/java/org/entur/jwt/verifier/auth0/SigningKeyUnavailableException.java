package org.entur.jwt.verifier.auth0;

import com.auth0.jwt.exceptions.JWTVerificationException;

public class SigningKeyUnavailableException extends JWTVerificationException {

	private static final long serialVersionUID = 1L;

	public SigningKeyUnavailableException(String message, Throwable cause) {
		super(message, cause);
	}

	public SigningKeyUnavailableException(String message) {
		super(message);
	}
	
}
