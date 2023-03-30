package org.entur.jwt.spring.grpc;

import org.lognet.springboot.grpc.GRpcGlobalInterceptor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.grpc.ServerInterceptor;

/**
 * 
 * Actually wire the interceptors
 * 
 */

@Configuration
public class GrpcConfiguration {

    /*
    @Bean
    @GRpcGlobalInterceptor
    public ServerInterceptor exceptionTranslationInterceptor(GrpcAuthenticationInterceptorFactory<?> wrapper) {
        return wrapper.getExceptionTranslationInterceptor();
    }
    
    @Bean
    @GRpcGlobalInterceptor
    @ConditionalOnMissingBean(JwtAuthenticationInterceptor.class)
    public JwtAuthenticationInterceptor<?> grpcAuth(GrpcAuthenticationInterceptorFactory<?> wrapper) {
        return wrapper.getJwtAuthenticationInterceptor();
    }
*/
}
