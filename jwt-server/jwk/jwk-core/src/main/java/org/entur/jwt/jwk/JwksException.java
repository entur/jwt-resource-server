package org.entur.jwt.jwk;

/**
 * Top-level Json Web Keys exception.<br><br>
 * <p>
 * Note: Do not subclass this directly, use the existing client- or server-type subclass.
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
