package org.entur.jwt.spring;

import org.entur.jwt.spring.properties.CorsProperties;
import org.entur.jwt.spring.properties.SecurityProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Configuration
@ConditionalOnProperty(name = {"entur.cors.enabled"}, havingValue = "true", matchIfMissing = true)
@AutoConfigureAfter(JwtAutoConfiguration.class)
public class JwtWebFluxAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(JwtWebFluxAutoConfiguration.class);

    @Bean("corsConfigurationSource")
    public CorsWebFilter corsConfigurationSource(SecurityProperties oidcAuthProperties) {
        CorsProperties cors = oidcAuthProperties.getCors();

        String mode = cors.getMode();
        if (mode.equals("api")) {
            return getCorsConfiguration(cors);
        } else if (mode.equals("webapp")) {
            if (!cors.getOrigins().isEmpty()) {
                throw new IllegalStateException("Expected empty hosts configuration for CORS mode '" + cors.getMode() + "'");
            }
            log.info("Disable CORS requests for webapp mode");

            return getEmptyCorsConfiguration();
        } else {
            throw new IllegalStateException("Unknown cors mode " + mode);
        }
    }

    public static CorsWebFilter getEmptyCorsConfiguration() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Collections.emptyList());
        config.setAllowedHeaders(Collections.emptyList());
        config.setAllowedMethods(Collections.emptyList());

        source.registerCorsConfiguration("/**", config);

        return new CorsWebFilter(source);
    }

    public static CorsWebFilter getCorsConfiguration(CorsProperties properties) {
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

        return new CorsWebFilter(source);
    }

}
