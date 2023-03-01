package org.entur.jwt.spring;

import org.entur.jwt.spring.auth0.properties.CorsProperties;
import org.entur.jwt.spring.auth0.properties.SecurityProperties;
import org.entur.jwt.spring.filter.JwtAuthenticationExceptionAdvice;
import org.entur.jwt.spring.filter.resolver.JwtArgumentResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true")
@AutoConfigureAfter(value = JwtAutoConfiguration.class)
public class JwtWebAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(JwtWebAutoConfiguration.class);

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
    @ConditionalOnMissingBean(JwtAuthenticationExceptionAdvice.class) // allow for customization
    public JwtAuthenticationExceptionAdvice advice() {
        return new JwtAuthenticationExceptionAdvice();
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
