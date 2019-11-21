package org.entur.jwt.verifier;

public class JwtClaimException extends JwtClientException {

	private static final long serialVersionUID = 1L;

	public JwtClaimException() {
		super();
	}

	public JwtClaimException(String message, Throwable cause) {
		super(message, cause);
	}

	public JwtClaimException(String message) {
		super(message);
	}

	public JwtClaimException(Throwable cause) {
		super(cause);
	}

}
