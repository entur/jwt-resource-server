package org.entur.jwt.spring;

import org.entur.jwt.spring.properties.CorsProperties;
import org.entur.jwt.spring.properties.SecurityProperties;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@ConditionalOnProperty(name = {"entur.cors.enabled"}, havingValue = "true", matchIfMissing = true)
@AutoConfigureAfter(value = JwtAutoConfiguration.class)
@EnableConfigurationProperties({SecurityProperties.class})
public class JwtWebAutoConfiguration {

    @Bean("corsConfigurationSource")
    public CorsConfigurationSource corsConfigurationSource(SecurityProperties oidcAuthProperties) {
        CorsConfigurationFactory factory = new CorsConfigurationFactory();

        return getCorsConfigurationSource(factory.create(oidcAuthProperties.getCors()));
    }

    public static CorsConfigurationSource getEmptyCorsConfiguration() {
        CorsConfigurationFactory factory = new CorsConfigurationFactory();

        return getCorsConfigurationSource(factory.createEmptyConfiguration());
    }

    public static CorsConfigurationSource getCorsConfiguration(CorsProperties properties) {
        CorsConfigurationFactory factory = new CorsConfigurationFactory();

        return getCorsConfigurationSource(factory.createApiConfiguration(properties));
    }

    private static CorsConfigurationSource getCorsConfigurationSource(CorsConfiguration config) {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }

}
