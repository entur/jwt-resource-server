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
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.result.method.annotation.ArgumentResolverConfigurer;

@ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true")
public class JwtAutoConfigurationWebFlux extends JwtAutoConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(JwtAutoConfigurationWebFlux.class);

    @Configuration
    public static class DefaultEnturWebFluxConfigurer implements WebFluxConfigurer {

        private final JwtArgumentResolver resolver;

        @Autowired
        public DefaultEnturWebFluxConfigurer(JwtArgumentResolver resolver) {
            this.resolver = resolver;
        }

        @Override
        public void configureArgumentResolvers(ArgumentResolverConfigurer configurer) {
            configurer.addCustomResolver(resolver);
        }
    }

    @Bean
    @ConditionalOnMissingBean(JwtServerAuthenticationConverter.class)
    public <T> JwtServerAuthenticationConverter<T> auth(SecurityProperties properties, JwtVerifier<T> verifier, @Autowired(required = false) JwtMappedDiagnosticContextMapper<T> mdcMapper, JwtAuthorityMapper<T> authorityMapper,
                                                        JwtClaimExtractor<T> extractor, JwtPrincipalMapper jwtPrincipalMapper, JwtDetailsMapper jwtDetailsMapper) {
        AuthorizationProperties authorizationProperties = properties.getAuthorization();

        PermitAll permitAll = authorizationProperties.getPermitAll();

        // add an extra layer of checks if auth is always required
        boolean tokenMustBePresent = authorizationProperties.isEnabled() && !permitAll.isActive();
        if (tokenMustBePresent) {
            LOG.info("Authentication with Json Web Token is required");
        } else {
            LOG.info("Authentication with Json Web Token is optional");
        }
        return new JwtServerAuthenticationConverter<>(verifier, authorityMapper, mdcMapper, extractor, tokenMustBePresent, jwtDetailsMapper, jwtPrincipalMapper);
    }

    @Bean
    @ConditionalOnMissingBean(JwtAuthenticationExceptionHandler.class) // allow for customization
    public JwtAuthenticationExceptionHandler advice() {
        return new JwtAuthenticationExceptionHandler();
    }

}
