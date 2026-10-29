package org.entur.jwt.spring;

import org.entur.jwt.spring.properties.CorsProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.cors.CorsConfiguration;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Builds the CORS configuration for the {@code entur.cors} properties; shared by the servlet and reactive web modules.
 */
public class CorsConfigurationFactory {

    private static final Logger log = LoggerFactory.getLogger(CorsConfigurationFactory.class);

    private static final List<String> DEFAULT_ALLOWED_METHODS = Arrays.asList("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS");
    private static final List<String> DEFAULT_ALLOWED_HEADERS = Collections.singletonList("*");

    public CorsConfiguration create(CorsProperties cors) {
        String mode = cors.getMode();
        if (mode.equals("api")) {
            return createApiConfiguration(cors);
        } else if (mode.equals("webapp")) {
            if (!cors.getOrigins().isEmpty()) {
                throw new IllegalStateException("Expected empty hosts configuration for CORS mode '" + cors.getMode() + "'");
            }
            log.info("Disable CORS requests for webapp mode");

            return createEmptyConfiguration();
        } else {
            throw new IllegalStateException("Unknown cors mode " + mode);
        }
    }

    public CorsConfiguration createEmptyConfiguration() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Collections.emptyList());
        config.setAllowedHeaders(Collections.emptyList());
        config.setAllowedMethods(Collections.emptyList());
        return config;
    }

    public CorsConfiguration createApiConfiguration(CorsProperties properties) {
        // the bare * is a plain origin, other values with wildcards are origin patterns like https://*.entur.org
        List<String> origins = new ArrayList<>();
        List<String> originPatterns = new ArrayList<>();
        for (String origin : properties.getOrigins()) {
            if (!origin.equals(CorsConfiguration.ALL) && origin.contains("*")) {
                originPatterns.add(origin);
            } else {
                origins.add(origin);
            }
        }

        boolean allowCredentials = isAllowCredentials(properties, origins.contains(CorsConfiguration.ALL));

        if (!properties.getOrigins().isEmpty()) {
            log.info("Enable CORS request with origins {}, methods {}, headers {} and allow credentials {} for API mode",
                    properties.getOrigins(),
                    properties.hasMethods() ? properties.getMethods() : "default (" + DEFAULT_ALLOWED_METHODS + ")",
                    properties.hasHeaders() ? properties.getHeaders() : "default (" + DEFAULT_ALLOWED_HEADERS + ")",
                    properties.getAllowCredentials() != null ? allowCredentials : "automatic (" + allowCredentials + ")"
            );
        }

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(origins);
        if (!originPatterns.isEmpty()) {
            config.setAllowedOriginPatterns(originPatterns);
        }
        if (properties.hasHeaders()) {
            config.setAllowedHeaders(properties.getHeaders());
        } else {
            config.setAllowedHeaders(DEFAULT_ALLOWED_HEADERS);
        }
        if (properties.hasMethods()) {
            config.setAllowedMethods(properties.getMethods());
        } else {
            config.setAllowedMethods(DEFAULT_ALLOWED_METHODS); // XXX
        }
        config.setMaxAge(86400L);
        config.setAllowCredentials(allowCredentials);
        return config;
    }

    private boolean isAllowCredentials(CorsProperties properties, boolean anyOrigin) {
        Boolean allowCredentials = properties.getAllowCredentials();
        if (allowCredentials == null) {
            // browsers do not accept credentials for any origin (*); access-tokens in the Authorization header do not need credentials
            return !anyOrigin;
        }
        if (allowCredentials && anyOrigin) {
            throw new IllegalStateException("CORS property entur.cors.allow-credentials=true cannot be combined with origin '*' in entur.cors.origins; "
                    + "list the origins explicitly, use origin patterns like https://*.example.com, or set entur.cors.allow-credentials=false");
        }
        return allowCredentials;
    }

}
