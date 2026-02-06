package org.entur.jwt.spring.grpc.netty;

import org.entur.jwt.spring.grpc.GrpcAuthorization;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Helper class for manual authorization checking.
 */

public interface SpringGrpcAuthorization extends GrpcAuthorization {

    default Authentication getAuthentication() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        if (securityContext != null) {
            return securityContext.getAuthentication();
        }
        return null;
    }

}
