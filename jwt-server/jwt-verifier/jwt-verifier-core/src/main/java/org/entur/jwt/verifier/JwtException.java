package org.entur.jwt.verifier;

/**
 * Top-level Jwt exception.<br><br>
 * <p>
 * Note: Do not subclass this directly, use the existing client- or server-type subclass.
 */

public class JwtException extends Exception {

    private static final long serialVersionUID = 1L;

    public JwtException() {
        super();
    }

    public JwtException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public JwtException(String message, Throwable cause) {
        super(message, cause);
    }

    public JwtException(String message) {
        super(message);
    }

    public JwtException(Throwable cause) {
        super(cause);
    }

}
