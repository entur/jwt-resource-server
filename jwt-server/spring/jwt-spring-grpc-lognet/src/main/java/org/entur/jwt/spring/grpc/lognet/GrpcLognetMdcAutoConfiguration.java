package org.entur.jwt.spring.grpc.lognet;

import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.grpc.GrpcMdcAdapter;
import org.entur.jwt.spring.grpc.properties.GrpcMdcProperties;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapperFactory;
import org.entur.jwt.spring.properties.MdcProperties;
import org.lognet.springboot.grpc.GRpcGlobalInterceptor;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnExpression("${entur.jwt.enabled:true}")
@EnableConfigurationProperties({GrpcMdcProperties.class, MdcProperties.class})
@AutoConfigureAfter(value = {JwtAutoConfiguration.class, org.lognet.springboot.grpc.autoconfigure.security.SecurityAutoConfiguration.class})
public class GrpcLognetMdcAutoConfiguration {

    @Bean
    @GRpcGlobalInterceptor
    @ConditionalOnBean(GrpcMdcAdapter.class)
    @ConditionalOnExpression("${entur.jwt.mdc.enabled:true}")
    public GrpcLognetMdcAuthorizationServerInterceptor mdcAuthorizationInterceptor(GrpcMdcAdapter adapter, MdcProperties mdcProperties, GrpcMdcProperties properties) throws Exception {
        int order = properties.getInterceptorOrder();

        JwtMappedDiagnosticContextMapperFactory factory = new JwtMappedDiagnosticContextMapperFactory();
        JwtMappedDiagnosticContextMapper mapper = factory.mapper(mdcProperties);

        return new GrpcLognetMdcAuthorizationServerInterceptor(mapper, order, adapter);
    }
}