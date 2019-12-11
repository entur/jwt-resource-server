package org.entur.jwt.jwk;

public class JwkNotFoundException extends JwksClientException {

    private static final long serialVersionUID = 1L;

    public JwkNotFoundException(String message) {
        super(message);
    }

    public JwkNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
