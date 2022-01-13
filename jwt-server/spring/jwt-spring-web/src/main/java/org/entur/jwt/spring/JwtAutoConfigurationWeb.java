package org.entur.jwt.spring;

import org.entur.jwt.spring.filter.*;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.entur.jwt.spring.filter.resolver.JwtArgumentResolver;
import org.entur.jwt.spring.properties.AuthorizationProperties;
import org.entur.jwt.spring.properties.PermitAll;
import org.entur.jwt.spring.properties.SecurityProperties;
import org.entur.jwt.verifier.JwtClaimExtractor;
import org.entur.jwt.verifier.JwtVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true")
public class JwtAutoConfigurationWeb extends JwtAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(JwtAutoConfigurationWeb.class);

    @Configuration
    public static class DefaultEnturWebMvcConfigurer implements WebMvcConfigurer {

        private final JwtArgumentResolver resolver;

        @Autowired
        public DefaultEnturWebMvcConfigurer(JwtArgumentResolver resolver) {
            this.resolver = resolver;
        }

        @Override
        public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
            resolvers.add(resolver);
        }
    }

    @Bean
    @ConditionalOnMissingBean(JwtAuthenticationFilter.class)
    public <T> JwtAuthenticationFilter<T> auth(SecurityProperties properties, JwtVerifier<T> verifier, @Autowired(required = false) JwtMappedDiagnosticContextMapper<T> mdcMapper, JwtAuthorityMapper<T> authorityMapper,
                                               JwtClaimExtractor<T> extractor, @Lazy HandlerExceptionResolver handlerExceptionResolver, JwtPrincipalMapper jwtPrincipalMapper, JwtDetailsMapper jwtDetailsMapper) {
        AuthorizationProperties authorizationProperties = properties.getAuthorization();

        PermitAll permitAll = authorizationProperties.getPermitAll();

        // add an extra layer of checks if auth is always required
        boolean tokenMustBePresent = authorizationProperties.isEnabled() && !permitAll.isActive();
        if (tokenMustBePresent) {
            log.info("Authentication with Json Web Token is required");
        } else {
            log.info("Authentication with Json Web Token is optional");
        }
        return new JwtAuthenticationFilter<>(verifier, tokenMustBePresent, authorityMapper, mdcMapper, extractor, handlerExceptionResolver, jwtPrincipalMapper, jwtDetailsMapper);
    }

    @Bean
    @ConditionalOnMissingBean(JwtAuthenticationExceptionAdvice.class) // allow for customization
    public JwtAuthenticationExceptionAdvice advice() {
        return new JwtAuthenticationExceptionAdvice();
    }

}
