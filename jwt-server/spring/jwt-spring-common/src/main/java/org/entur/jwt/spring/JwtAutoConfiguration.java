package org.entur.jwt.spring;

import org.entur.jwt.spring.actuate.ListJwksHealthIndicator;
import org.entur.jwt.spring.decode.BoundedJwtHeaderToIssuerMapper;
import org.entur.jwt.spring.decode.ClosableJwtDecoders;
import org.entur.jwt.spring.decode.ClosableJwtDecodersBuilder;
import org.entur.jwt.spring.decode.cache.DecodedJwtCacheConfigurationReader;
import org.entur.jwt.spring.decode.DefaultJwtHeaderToIssuerMapperDecider;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapperDecider;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.entur.jwt.spring.properties.JwtProperties;
import org.entur.jwt.spring.properties.SecurityProperties;
import org.entur.jwt.spring.properties.jwk.JwtTenantProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.health.autoconfigure.contributor.ConditionalOnEnabledHealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
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
        return new ListJwksHealthIndicator(Executors.newCachedThreadPool(), "List");
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

    @Bean
    @ConditionalOnProperty(name = "entur.jwt.decode.header.map-to-issuer.enabled", havingValue = "true")
    @ConditionalOnMissingBean(JwtHeaderToIssuerMapper.class)
    public JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper(SecurityProperties securityProperties) {
        int maxSize = securityProperties.getJwt().getDecode().getHeader().getMapToIssuer().getMaxSize();
        return maxSize != -1 ? new BoundedJwtHeaderToIssuerMapper(maxSize) : new JwtHeaderToIssuerMapper();
    }

    /**
     * Per-issuer JWT decoders (including any decoded JWT caches), shared by the web and gRPC modules,
     * and closed by Spring on shutdown. Lazy, so that it is only created if used (i.e. not for webflux).
     * Intentionally not a {@link org.springframework.security.oauth2.jwt.JwtDecoder} bean, as that would activate
     * Spring Boot's default resource server security filter chain.
     */
    @Bean
    @Lazy
    @ConditionalOnMissingBean(ClosableJwtDecoders.class)
    public ClosableJwtDecoders closableJwtDecoders(JwkSourceMap jwkSourceMap, List<OAuth2TokenValidator<Jwt>> jwtValidators, SecurityProperties securityProperties) {
        return new ClosableJwtDecodersBuilder()
                .withJwkSources(jwkSourceMap.getJwkSources())
                .withJwkEventListeners(jwkSourceMap.getJwkEventListeners())
                .withJwtValidators(jwtValidators)
                .withDecodedJwtCacheIssuers(DecodedJwtCacheConfigurationReader.getActiveJwtDecoderCacheProperties(securityProperties.getJwt()))
                .build();
    }

    @Bean
    @ConditionalOnProperty(name = "entur.jwt.decode.header.map-to-issuer.enabled", havingValue = "true")
    @ConditionalOnMissingBean(JwtHeaderToIssuerMapperDecider.class)
    public JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider() {
        return new DefaultJwtHeaderToIssuerMapperDecider();
    }

}
