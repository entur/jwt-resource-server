package org.entur.jwt.spring.grpc.ecosystem;

import net.devh.boot.grpc.server.security.interceptors.AuthenticatingServerInterceptor;
import org.entur.jwt.spring.grpc.GrpcAuthorization;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;

/**
 * Helper class for manual authorization checking.
 */

public interface EcosystemGrpcAuthorization extends GrpcAuthorization {

    default Authentication getAuthentication() {
        SecurityContext securityContext = AuthenticatingServerInterceptor.SECURITY_CONTEXT_KEY.get();
        if (securityContext != null) {
            return securityContext.getAuthentication();
        }
        return null;
    }

}
