package org.entur.jwt.spring.grpc;

import io.grpc.ServerInterceptor;

/**
 * 
 * Wrap interceptors so that projects can wire their own ordering.
 * 
 * See also https://github.com/LogNet/grpc-spring-boot-starter/issues/117
 *
 */

public class GrpcAuthenticationInterceptorFactory<T> {

    private final JwtAuthenticationInterceptor<T> jwtAuthenticationInterceptor;
    private final AuthenticationExceptionTranslationInterceptor authenticationExceptionTranslationInterceptor = new AuthenticationExceptionTranslationInterceptor();
    
    public GrpcAuthenticationInterceptorFactory(JwtAuthenticationInterceptor<T> jwtAuthenticationInterceptor) {
        this.jwtAuthenticationInterceptor = jwtAuthenticationInterceptor;
    }

    public ServerInterceptor getAuthenticationExceptionTranslatorInterceptor() {
        return authenticationExceptionTranslationInterceptor;
    }
    
    public JwtAuthenticationInterceptor<T> getJwtAuthenticationInterceptor() {
        return jwtAuthenticationInterceptor;
    }
    
}
