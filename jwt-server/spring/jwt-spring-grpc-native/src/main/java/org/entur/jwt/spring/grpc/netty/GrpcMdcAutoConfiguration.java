package org.entur.jwt.spring.grpc.netty;

import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapperFactory;
import org.entur.jwt.spring.grpc.GrpcMdcAdapter;
import org.entur.jwt.spring.grpc.properties.GrpcMdcProperties;
import org.entur.jwt.spring.properties.MdcProperties;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.grpc.server.autoconfigure.security.GrpcServerOAuth2ResourceServerAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.server.security.GrpcSecurity;

@Configuration
@ConditionalOnExpression("${entur.jwt.enabled:true}")
@EnableConfigurationProperties({GrpcMdcProperties.class, MdcProperties.class})
@AutoConfigureAfter(value = {JwtAutoConfiguration.class, GrpcServerOAuth2ResourceServerAutoConfiguration.class})
public class GrpcMdcAutoConfiguration {

    /** Interceptors run in ascending order, so this is after the authentication interceptor has put the JWT in the security context. */
    static final int DEFAULT_INTERCEPTOR_ORDER = GrpcSecurity.CONTEXT_FILTER_ORDER + 1;

    @Bean
    @ConditionalOnBean(GrpcMdcAdapter.class)
    @ConditionalOnExpression("${entur.jwt.mdc.enabled:true}")
    public GrpcMdcAuthorizationServerInterceptor mdcAuthorizationInterceptor(GrpcMdcAdapter adapter, MdcProperties mdcProperties, GrpcMdcProperties properties) {
        int order = properties.getInterceptorOrder() != null ? properties.getInterceptorOrder() : DEFAULT_INTERCEPTOR_ORDER;

        JwtMappedDiagnosticContextMapperFactory factory = new JwtMappedDiagnosticContextMapperFactory();
        JwtMappedDiagnosticContextMapper mapper = factory.mapper(mdcProperties);

        return new GrpcMdcAuthorizationServerInterceptor(mapper, order, adapter);
    }
}