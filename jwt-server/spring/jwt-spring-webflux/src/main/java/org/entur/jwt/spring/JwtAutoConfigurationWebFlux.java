package org.entur.jwt.spring;

import org.entur.jwt.spring.filter.JwtAuthenticationExceptionHandler;
import org.entur.jwt.spring.filter.JwtAuthenticationManager;
import org.entur.jwt.spring.filter.JwtAuthorityMapper;
import org.entur.jwt.spring.filter.JwtDetailsMapper;
import org.entur.jwt.spring.filter.JwtPrincipalMapper;
import org.entur.jwt.spring.filter.JwtServerAuthenticationConverter;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.entur.jwt.spring.filter.resolver.JwtArgumentResolver;
import org.entur.jwt.spring.properties.AuthorizationProperties;
import org.entur.jwt.spring.properties.CorsProperties;
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
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.result.method.annotation.ArgumentResolverConfigurer;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true")
public class JwtAutoConfigurationWebFlux extends JwtAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(JwtAutoConfigurationWebFlux.class);

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
            log.info("Authentication with Json Web Token is required");
        } else {
            log.info("Authentication with Json Web Token is optional");
        }
        return new JwtServerAuthenticationConverter<>(verifier, authorityMapper, mdcMapper, extractor, tokenMustBePresent, jwtDetailsMapper, jwtPrincipalMapper);
    }

    @Bean
    @ConditionalOnMissingBean(JwtAuthenticationExceptionHandler.class) // allow for customization
    public JwtAuthenticationExceptionHandler advice() {
        return new JwtAuthenticationExceptionHandler();
    }

    @Bean
    @ConditionalOnMissingBean(ReactiveAuthenticationManager.class)
    @ConditionalOnProperty(name = "entur.jwt.enabled", havingValue = "true")
    public ReactiveAuthenticationManager reactiveAuthenticationManager() {
        return new JwtAuthenticationManager();
    }

    @Bean
    @ConditionalOnMissingBean(CustomAuthenticationFailureHandler.class)
    @ConditionalOnProperty(name = "entur.jwt.enabled", havingValue = "true")
    public CustomAuthenticationFailureHandler customAuthenticationFailureHandler() {
        return new CustomAuthenticationFailureHandler();
    }

    @Bean
    @ConditionalOnMissingBean(CustomServerAuthenticationEntryPoint.class)
    @ConditionalOnProperty(name = "entur.jwt.enabled", havingValue = "true")
    public CustomServerAuthenticationEntryPoint customServerAuthenticationEntryPoint() {
        return new CustomServerAuthenticationEntryPoint();
    }

    @Bean("corsConfigurationSource")
    @ConditionalOnProperty(name = {"entur.cors.enabled"}, havingValue = "true")
    public CorsConfigurationSource corsConfigurationSource(SecurityProperties oidcAuthProperties) {
        CorsProperties cors = oidcAuthProperties.getCors();
        if (cors.getMode().equals("api")) {
            return getCorsConfiguration(cors);
        } else {
            if (!cors.getOrigins().isEmpty()) {
                throw new IllegalStateException("Expected empty hosts configuration for CORS mode '" + cors.getMode() + "'");
            }
            log.info("Disable CORS requests for webapp mode");

            return getEmptyCorsConfiguration();
        }
    }

    @Bean("corsConfigurationSource")
    @ConditionalOnProperty(name = {"entur.security.cors.mode"}, havingValue = "webapp")
    public CorsConfigurationSource corsConfigurationSourceForWebapp(SecurityProperties properties) {
        log.info("Disable CORS requests for webapp mode");
        return getEmptyCorsConfiguration();
    }

    public static CorsConfigurationSource getEmptyCorsConfiguration() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Collections.emptyList());
        config.setAllowedHeaders(Collections.emptyList());
        config.setAllowedMethods(Collections.emptyList());

        source.registerCorsConfiguration("/**", config);

        return source;
    }

    public static CorsConfigurationSource getCorsConfiguration(CorsProperties properties) {
        List<String> defaultAllowedMethods = Arrays.asList("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS");
        List<String> defaultAllowedHeaders = Collections.singletonList("*");

        List<String> origins = properties.getOrigins();
        log.info("Enable CORS request with origins {}, methods {} and headers {} for API mode",
                properties.getOrigins(),
                properties.hasMethods() ? properties.getMethods() : "default (" + defaultAllowedMethods + ")",
                properties.hasHeaders() ? properties.getHeaders() : "default (" + defaultAllowedHeaders + ")"
        );

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(origins);
        if (properties.hasHeaders()) {
            config.setAllowedHeaders(properties.getHeaders());
        } else {
            config.setAllowedHeaders(defaultAllowedHeaders);
        }
        if (properties.hasMethods()) {
            config.setAllowedMethods(properties.getMethods());
        } else {
            config.setAllowedMethods(defaultAllowedMethods); // XXX
        }
        config.setMaxAge(86400L);
        config.setAllowCredentials(true);
        source.registerCorsConfiguration("/**", config);

        return source;
    }

}
