package org.entur.jwt.spring.grpc;

import java.util.List;

import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.filter.JwtAuthorityMapper;
import org.entur.jwt.spring.filter.JwtDetailsMapper;
import org.entur.jwt.spring.filter.JwtPrincipalMapper;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.entur.jwt.spring.grpc.exception.ServerCallRuntimeExceptionTranslator;
import org.entur.jwt.spring.grpc.exception.ServerCallSecurityExceptionTranslator;
import org.entur.jwt.spring.grpc.exception.ServerCallStatusRuntimeExceptionTranslator;
import org.entur.jwt.spring.grpc.properties.GrpcPermitAll;
import org.entur.jwt.spring.grpc.properties.GrpcServicesConfiguration;
import org.entur.jwt.spring.grpc.properties.ServiceMatcherConfiguration;
import org.entur.jwt.spring.properties.SecurityProperties;
import org.entur.jwt.verifier.JwtClaimExtractor;
import org.entur.jwt.verifier.JwtVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.web.servlet.HandlerExceptionResolver;

import io.grpc.util.TransmitStatusRuntimeExceptionInterceptor;

@Configuration
@EnableConfigurationProperties({ GrpcPermitAll.class })
@ConditionalOnProperty(name = { "entur.jwt.enabled" }, havingValue = "true", matchIfMissing = false)
@AutoConfigureAfter(value = JwtAutoConfiguration.class)
public class GrpcAutoConfiguration {

    private static Logger log = LoggerFactory.getLogger(GrpcAutoConfiguration.class);
    
    @Bean
    public ServerCallSecurityExceptionTranslator serverCallSecurityExceptionTranslator() {
    	return new ServerCallSecurityExceptionTranslator();
    }
    
    @Bean
    @ConditionalOnMissingBean(TransmitStatusRuntimeExceptionInterceptor.class)
    public ServerCallStatusRuntimeExceptionTranslator serverCallStatusRuntimeExceptionTranslator() {
    	return new ServerCallStatusRuntimeExceptionTranslator();
    }    
    
    @Bean
    public <T> GrpcAuthenticationInterceptorFactory<T> grpcAuthenticationInterceptorFactory(SecurityProperties properties, JwtVerifier<T> verifier, @Autowired(required = false) JwtMappedDiagnosticContextMapper<T> mdcMapper, JwtAuthorityMapper<T> authorityMapper,
            JwtClaimExtractor<T> extractor, @Lazy HandlerExceptionResolver handlerExceptionResolver, GrpcPermitAll permitAll, JwtPrincipalMapper jwtPrincipalMapper, JwtDetailsMapper jwtDetailsMapper, List<ServerCallRuntimeExceptionTranslator> translators) {

        // add an extra layer of checks if auth is always required
        GrpcServiceMethodFilter anonymous;
        if(permitAll.isActive()) {
            anonymous = getGrpcServiceMethodFilter(permitAll.getGrpc());
        } else {
            log.info("No anonymous GRPC calls allowed");
            anonymous = null;
        }
        
        JwtAuthenticationInterceptor<T> jwtAuthenticationInterceptor = new JwtAuthenticationInterceptor<>(verifier, anonymous, authorityMapper, mdcMapper, extractor, jwtPrincipalMapper, jwtDetailsMapper);
        return new GrpcAuthenticationInterceptorFactory<>(jwtAuthenticationInterceptor, translators);
    }

    private GrpcServiceMethodFilter getGrpcServiceMethodFilter(GrpcServicesConfiguration grpc) {
        DefaultGrpcServiceMethodFilter filter = new DefaultGrpcServiceMethodFilter();
                
        for (ServiceMatcherConfiguration configuration : grpc.getServices()) {
            if(isStar(configuration.getMethods())) {
                log.info("Allow anonymous access to all methods of GRPC service " + configuration.getName());
                filter.addService(configuration.getName());
            } else {
                log.info("Allow anonymous access to methods " + configuration.getMethods() + " of GRPC service " + configuration.getName());
                for (String string : configuration.getMethods()) {
                    filter.addServiceMethod(configuration.getName(), string);
                }
            }
        }
                
        return filter;
    }

    private boolean isStar(List<String> methods) {
        for (String string : methods) {
            if(string.equals("*")) {
                return true;
            }
        }
        return false;
    }
}
