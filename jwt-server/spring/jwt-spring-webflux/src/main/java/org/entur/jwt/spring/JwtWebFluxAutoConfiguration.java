package org.entur.jwt.spring;

import org.entur.jwt.spring.properties.CorsProperties;
import org.entur.jwt.spring.properties.SecurityProperties;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

@Configuration
@ConditionalOnProperty(name = {"entur.cors.enabled"}, havingValue = "true", matchIfMissing = true)
@AutoConfigureAfter(JwtAutoConfiguration.class)
@EnableConfigurationProperties({SecurityProperties.class})
public class JwtWebFluxAutoConfiguration {

    // run before the spring security web filter chain (order -100), so that CORS requests are handled
    // before authentication, as preflight requests do not carry credentials
    private static final int CORS_FILTER_ORDER = -101;

    @Bean("corsConfigurationSource")
    @Order(CORS_FILTER_ORDER)
    public CorsWebFilter corsConfigurationSource(SecurityProperties oidcAuthProperties) {
        CorsConfigurationFactory factory = new CorsConfigurationFactory();

        return getCorsWebFilter(factory.create(oidcAuthProperties.getCors()));
    }

    public static CorsWebFilter getEmptyCorsConfiguration() {
        CorsConfigurationFactory factory = new CorsConfigurationFactory();

        return getCorsWebFilter(factory.createEmptyConfiguration());
    }

    public static CorsWebFilter getCorsConfiguration(CorsProperties properties) {
        CorsConfigurationFactory factory = new CorsConfigurationFactory();

        return getCorsWebFilter(factory.createApiConfiguration(properties));
    }

    private static CorsWebFilter getCorsWebFilter(CorsConfiguration config) {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return new CorsWebFilter(source);
    }

}
