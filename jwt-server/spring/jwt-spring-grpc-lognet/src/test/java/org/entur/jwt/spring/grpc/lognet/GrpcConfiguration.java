package org.entur.jwt.spring.grpc.lognet;

import org.springframework.context.annotation.Configuration;

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
