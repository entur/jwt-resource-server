package org.entur.jwt.spring.grpc;

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
    @GrpcGlobalInterceptor
    public ServerInterceptor exceptionTranslationInterceptor(GrpcAuthenticationInterceptorFactory<?> wrapper) {
        return wrapper.getExceptionTranslationInterceptor();
    }
    
    @Bean
    @GrpcGlobalInterceptor
    @ConditionalOnMissingBean(JwtAuthenticationInterceptor.class)
    public JwtAuthenticationInterceptor<?> grpcAuth(GrpcAuthenticationInterceptorFactory<?> wrapper) {
        return wrapper.getJwtAuthenticationInterceptor();
    }
*/
}
