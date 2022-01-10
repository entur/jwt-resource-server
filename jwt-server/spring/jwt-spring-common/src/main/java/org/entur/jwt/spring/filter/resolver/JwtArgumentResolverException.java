package org.entur.jwt.spring.filter.resolver;

import org.springframework.security.access.AccessDeniedException;

public class JwtArgumentResolverException extends AccessDeniedException {

    private static final long serialVersionUID = 1L;

    public JwtArgumentResolverException(String msg) {
        super(msg);
    }

    public JwtArgumentResolverException(String msg, Throwable t) {
        super(msg, t);
    }

}