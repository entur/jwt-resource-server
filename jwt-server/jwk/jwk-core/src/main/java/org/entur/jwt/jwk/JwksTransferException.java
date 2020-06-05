package org.entur.jwt.jwk;

public class JwksTransferException extends JwksUnavailableException {

	private static final long serialVersionUID = 1L;

	public JwksTransferException(String message, Throwable cause) {
		super(message, cause);
	}

	public JwksTransferException(String message) {
		super(message);
	}

	public JwksTransferException(Throwable cause) {
		super(cause);
	}
	
}
