package org.entur.jwt.spring.decode;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.entur.jwt.spring.decode.cache.DecodedJwtCacheJwtDecoder;
import org.entur.jwt.spring.properties.jwk.JwtDecoderCacheProperties;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;

/**
 *
 * Builds a per-issuer {@link JwtDecoder} map, wrapped in a {@link ClosableJwtDecoders} so that
 * caching decoders can be closed by Spring when the context shuts down.
 *
 */

public class ClosableJwtDecodersBuilder {

    private List<OAuth2TokenValidator<Jwt>> jwtValidators;
    private Map<String, JWKSource> jwkSources;
    private Map<String, JwtDecoderCacheProperties> decodedJwtCacheIssuers;

    public ClosableJwtDecodersBuilder withJwkSources(Map<String, JWKSource> jwkSources) {
        this.jwkSources = jwkSources;
        return this;
    }

    public ClosableJwtDecodersBuilder withJwtValidators(List<OAuth2TokenValidator<Jwt>> jwtValidators) {
        this.jwtValidators = jwtValidators;
        return this;
    }

    public ClosableJwtDecodersBuilder withDecodedJwtCacheIssuers(Map<String, JwtDecoderCacheProperties> decodedJwtCacheIssuers) {
        this.decodedJwtCacheIssuers = decodedJwtCacheIssuers;
        return this;
    }

    /**
     * Build the per-issuer {@link JwtDecoder}s, wrapped so that Spring can close any underlying
     * caching resources on context shutdown.
     */
    public ClosableJwtDecoders build() {
        Map<String, JwtDecoder> map = HashMap.newHashMap(jwkSources.size() * 4);
        List<AutoCloseable> resources = new ArrayList<>();

        // background cleanup and eviction for all decoded JWT caches, on a single thread
        ScheduledExecutorService scheduledExecutorService = null;

        for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {
            JWKSource jwkSource = entry.getValue();

            DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.Family.SIGNATURE, jwkSource);
            jwtProcessor.setJWSKeySelector(keySelector);
            // the claims (including expiry) are validated by the JWT validators, so disable the Nimbus verifier,
            // which would otherwise limit the leeway to its own (one minute) clock skew
            jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
            });

            NimbusJwtDecoder nimbusJwtDecoder = new NimbusJwtDecoder(jwtProcessor);
            DelegatingOAuth2TokenValidator<Jwt> validators = JwtDecoderValidators.create(entry.getKey(), jwtValidators);
            nimbusJwtDecoder.setJwtValidator(validators);

            JwtDecoder decoder = nimbusJwtDecoder;

            JwtDecoderCacheProperties cacheProperties = decodedJwtCacheIssuers != null ? decodedJwtCacheIssuers.get(entry.getKey()) : null;
            if (cacheProperties != null) {
                if (scheduledExecutorService == null) {
                    scheduledExecutorService = DecodedJwtCacheJwtDecoder.createDefaultScheduledExecutorService();
                    resources.add(scheduledExecutorService::shutdownNow);
                }
                // checks cached JWTs against the same JWK source as the decoder
                decoder = new DecodedJwtCacheJwtDecoder(entry.getKey(), decoder, jwkSource, validators, cacheProperties.getCleanupInterval() * 1000L, cacheProperties.getSize(), cacheProperties.getMode(), scheduledExecutorService);
            }

            map.put(entry.getKey(), decoder);
        }

        return new ClosableJwtDecoders(map, resources);
    }
}
