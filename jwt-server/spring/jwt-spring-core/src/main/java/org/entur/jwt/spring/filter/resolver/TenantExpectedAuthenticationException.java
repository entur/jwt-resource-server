package org.entur.jwt.spring.filter.resolver;

import org.springframework.security.access.AccessDeniedException;

public class TenantExpectedAuthenticationException extends AccessDeniedException {

    private static final long serialVersionUID = 1L;

    public TenantExpectedAuthenticationException(String msg) {
        super(msg);
    }

    public TenantExpectedAuthenticationException(String msg, Throwable t) {
        super(msg, t);
    }

}