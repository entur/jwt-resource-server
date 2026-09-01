package org.entur.jwt.spring.decode;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.entur.jwt.spring.actuate.ListEventListener;
import org.entur.jwt.spring.decode.cache.DecodedJwtCacheJwtDecoder;
import org.entur.jwt.spring.properties.jwk.JwtDecoderCacheProperties;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * Builds a per-issuer {@link JwtDecoder} map, wrapped in a {@link ClosableJwtDecoders} so that
 * caching decoders can be closed by Spring when the context shuts down.
 *
 */

public class ClosableJwtDecodersBuilder {

    private List<OAuth2TokenValidator<Jwt>> jwtValidators;
    private Map<String, JWKSource> jwkSources;
    private Map<String, ListEventListener> jwkEventListeners;
    private Map<String, JwtDecoderCacheProperties> decodedJwtCacheIssuers;

    public ClosableJwtDecodersBuilder withJwkEventListeners(Map<String, ListEventListener> jwkEventListeners) {
        this.jwkEventListeners = jwkEventListeners;
        return this;
    }

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
        Map<String, JwtDecoder> map = new HashMap<>(jwkSources.size() * 4);

        for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {
            JWKSource jwkSource = entry.getValue();

            DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.Family.SIGNATURE, jwkSource);
            jwtProcessor.setJWSKeySelector(keySelector);

            NimbusJwtDecoder nimbusJwtDecoder = new NimbusJwtDecoder(jwtProcessor);
            DelegatingOAuth2TokenValidator<Jwt> validators = getJwtValidators(entry.getKey());
            nimbusJwtDecoder.setJwtValidator(validators);

            JwtDecoder decoder = nimbusJwtDecoder;

            if (decodedJwtCacheIssuers != null) {
                JwtDecoderCacheProperties cacheProperties = decodedJwtCacheIssuers.get(entry.getKey());
                if (cacheProperties != null) {
                    ListEventListener eventListener = jwkEventListeners.get(entry.getKey());
                    if (eventListener != null) {
                        DecodedJwtCacheJwtDecoder cachedDecoder = new DecodedJwtCacheJwtDecoder(decoder, validators, cacheProperties.getCleanupInterval() * 1000L, cacheProperties.getMaxSize());
                        cachedDecoder.scheduleCleanup();
                        eventListener.addEventListener(cachedDecoder);
                        decoder = cachedDecoder;
                    }
                }
            }

            map.put(entry.getKey(), decoder);
        }

        return new ClosableJwtDecoders(map);
    }

    private DelegatingOAuth2TokenValidator<Jwt> getJwtValidators(String issuer) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtIssuerValidator(issuer));
        validators.addAll(jwtValidators);
        return new DelegatingOAuth2TokenValidator<>(validators);
    }
}
