package org.entur.jwt.spring.grpc;

import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.grpc.properties.GrpcMdcProperties;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapperFactory;
import org.entur.jwt.spring.properties.MdcProperties;
import org.lognet.springboot.grpc.GRpcGlobalInterceptor;
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
@EnableConfigurationProperties({GrpcMdcProperties.class, MdcProperties.class})
@AutoConfigureAfter(value = {JwtAutoConfiguration.class, org.lognet.springboot.grpc.autoconfigure.security.SecurityAutoConfiguration.class})
public class GrpcMdcAutoConfiguration {

    @Bean
    @GRpcGlobalInterceptor
    @ConditionalOnBean(GrpcMdcAdapter.class)
    @ConditionalOnExpression("${entur.jwt.mdc.enabled:true}")
    public MdcAuthorizationServerInterceptor mdcAuthorizationInterceptor(GrpcMdcAdapter adapter, MdcProperties mdcProperties, GrpcMdcProperties properties, @Value("${grpc.security.auth.interceptor-order:-1}") int defaultOrder) throws Exception {

        Integer order = properties.getInterceptorOrder();
        if(order == null) {
            order = 1 + (defaultOrder != -1 ? defaultOrder : Ordered.HIGHEST_PRECEDENCE);
        }

        JwtMappedDiagnosticContextMapperFactory factory = new JwtMappedDiagnosticContextMapperFactory();
        JwtMappedDiagnosticContextMapper mapper = factory.mapper(mdcProperties);

        return new MdcAuthorizationServerInterceptor(mapper, order, adapter);
    }
}