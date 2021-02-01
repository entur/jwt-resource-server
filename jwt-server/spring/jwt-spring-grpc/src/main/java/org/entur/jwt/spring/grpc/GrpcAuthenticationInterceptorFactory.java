package org.entur.jwt.spring.grpc;

import java.util.List;

import org.entur.jwt.spring.grpc.exception.GrpcRuntimeExceptionTranslationInterceptor;
import org.entur.jwt.spring.grpc.exception.ServerCallRuntimeExceptionTranslator;

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
    private final GrpcRuntimeExceptionTranslationInterceptor exceptionTranslationInterceptor;
    
    public GrpcAuthenticationInterceptorFactory(JwtAuthenticationInterceptor<T> jwtAuthenticationInterceptor, List<ServerCallRuntimeExceptionTranslator> translators) {
        this.jwtAuthenticationInterceptor = jwtAuthenticationInterceptor;
        this.exceptionTranslationInterceptor = new GrpcRuntimeExceptionTranslationInterceptor(translators);
    }

    @Deprecated
    public ServerInterceptor getAuthenticationExceptionTranslatorInterceptor() {
        return exceptionTranslationInterceptor;
    }
    
    public GrpcRuntimeExceptionTranslationInterceptor getExceptionTranslationInterceptor() {
        return exceptionTranslationInterceptor;
    }
    
   
    public JwtAuthenticationInterceptor<T> getJwtAuthenticationInterceptor() {
        return jwtAuthenticationInterceptor;
    }
    
}
