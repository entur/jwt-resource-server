package org.entur.jwt.spring;

import org.entur.jwt.spring.actuate.ListJwksHealthIndicator;
import org.entur.jwt.spring.properties.JwtProperties;
import org.entur.jwt.spring.properties.SecurityProperties;
import org.entur.jwt.spring.properties.jwk.JwkProperties;
import org.entur.jwt.spring.properties.jwk.JwtTenantProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.autoconfigure.health.ConditionalOnEnabledHealthIndicator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.Executors;

@Configuration
@EnableConfigurationProperties({SecurityProperties.class})
@ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true")
public class JwtAutoConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(JwtAutoConfiguration.class);

    @Bean(destroyMethod = "close", value = "jwks")
    @ConditionalOnEnabledHealthIndicator("jwks")
    public ListJwksHealthIndicator jwksHealthIndicator(SecurityProperties properties) {
        JwtProperties jwtProperties = properties.getJwt();
        JwkProperties jwk = jwtProperties.getJwk();

        // TODO should also the number of active provides be taken into account? Don't want the
        // health check http response to time out

        long maxDelay = (jwk.getConnectTimeout() + jwk.getReadTimeout()) * 1000;

        return new ListJwksHealthIndicator(maxDelay, Executors.newCachedThreadPool(), "List");
    }

    @Bean(destroyMethod = "close")
    @ConditionalOnMissingBean(JwkSourceMap.class)
    public JwkSourceMap jwkSourceMap(SecurityProperties properties, @Autowired(required = false) ListJwksHealthIndicator listJwksHealthIndicator) {
        JwtProperties jwtProperties = properties.getJwt();

        Map<String, JwtTenantProperties> enabledTenants = new HashMap<>();
        for (Entry<String, JwtTenantProperties> entry : jwtProperties.getTenants().entrySet()) {
            if (entry.getValue().isEnabled()) {
                enabledTenants.put(entry.getKey(), entry.getValue());
            }
        }
        if (enabledTenants.isEmpty()) {
            Set<String> disabled = new HashSet<>(jwtProperties.getTenants().keySet());
            disabled.removeAll(enabledTenants.keySet());
            throw new IllegalStateException("No configured tenants (" + disabled + " were disabled)");
        }

        JwkSourceMapFactory factory = new JwkSourceMapFactory();

        // add a wrapper so that the verifier is closed on shutdown
        return factory.getJwkSourceMap(enabledTenants, jwtProperties.getJwk(), listJwksHealthIndicator);
    }

    @Bean
    public List<OAuth2TokenValidator<Jwt>> claimConstraints(SecurityProperties properties) {
        OAuth2TokenValidatorFactory oAuth2TokenValidatorFactory = new OAuth2TokenValidatorFactory();

        return oAuth2TokenValidatorFactory.create(properties.getJwt().getClaims());
    }



}
