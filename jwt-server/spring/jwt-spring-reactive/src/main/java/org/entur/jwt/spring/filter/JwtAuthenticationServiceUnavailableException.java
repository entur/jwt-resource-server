package org.entur.jwt.spring.filter;

import org.springframework.security.authentication.AuthenticationServiceException;

public class JwtAuthenticationServiceUnavailableException extends AuthenticationServiceException {

    private static final long serialVersionUID = 1L;

    public JwtAuthenticationServiceUnavailableException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public JwtAuthenticationServiceUnavailableException(String msg) {
        super(msg);
    }

}
