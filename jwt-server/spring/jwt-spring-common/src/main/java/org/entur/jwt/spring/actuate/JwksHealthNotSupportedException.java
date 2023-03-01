package org.entur.jwt.spring.actuate;

public class JwksHealthNotSupportedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public JwksHealthNotSupportedException(String message) {
        super(message);
    }

}