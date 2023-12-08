package org.entur.jwt.spring.grpc;

import io.grpc.ServerInterceptor;
import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.properties.MdcProperties;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapperFactory;
import org.lognet.springboot.grpc.GRpcGlobalInterceptor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration
@ConditionalOnExpression("${entur.jwt.enabled:true}")
@EnableConfigurationProperties({MdcProperties.class})
@AutoConfigureAfter(value = {JwtAutoConfiguration.class, org.lognet.springboot.grpc.autoconfigure.security.SecurityAutoConfiguration.class})
public class GrpcMdcAutoConfiguration {

    @Bean
    @GRpcGlobalInterceptor
    @ConditionalOnBean(GrpcMdcAdapter.class)
    @ConditionalOnExpression("${entur.jwt.mdc.enabled:true}")
    public MdcAuthorizationServerInterceptor mdcAuthorizationInterceptor(@Value("${grpc.security.auth.interceptor-order:-1}") int order, MdcProperties properties, GrpcMdcAdapter adapter) throws Exception {
        int interceptorOrder = order != -1 ? order : Ordered.HIGHEST_PRECEDENCE+1;

        JwtMappedDiagnosticContextMapperFactory factory = new JwtMappedDiagnosticContextMapperFactory();
        JwtMappedDiagnosticContextMapper mapper = factory.mapper(properties);

        return new MdcAuthorizationServerInterceptor(mapper, interceptorOrder + 1, adapter);
    }
}