package org.entur.jwt.spring.filter.resolver;

import org.springframework.security.access.AccessDeniedException;

public class UnexpectedJwtArgumentResolverResultException extends AccessDeniedException {

    private static final long serialVersionUID = 1L;

    public UnexpectedJwtArgumentResolverResultException(String msg) {
        super(msg);
    }

    public UnexpectedJwtArgumentResolverResultException(String msg, Throwable t) {
        super(msg, t);
    }
    
}