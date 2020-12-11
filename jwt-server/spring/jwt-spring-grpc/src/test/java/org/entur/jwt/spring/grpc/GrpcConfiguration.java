package org.entur.jwt.spring.grpc;

import org.lognet.springboot.grpc.GRpcGlobalInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    @Bean
    @GRpcGlobalInterceptor
    public ServerInterceptor authenticationExceptionTranslatorInterceptor(GrpcAuthenticationInterceptorFactory<?> wrapper) {
        return wrapper.getAuthenticationExceptionTranslatorInterceptor();
    }
    
    @Bean
    @GRpcGlobalInterceptor
    @ConditionalOnMissingBean(JwtAuthenticationInterceptor.class)
    public JwtAuthenticationInterceptor<?> grpcAuth(GrpcAuthenticationInterceptorFactory<?> wrapper) {
        return wrapper.getJwtAuthenticationInterceptor();
    }

}
