package org.entur.jwt.spring.decode;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.entur.jwt.spring.actuate.ListEventListener;
import org.entur.jwt.spring.decode.cache.DecodedJwtCacheJwkEventListener;
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
        // validate every issuer before creating anything: if the build fails there is no ClosableJwtDecoders to close
        // what was already created (i.e. cleanup threads and JWK event listener registrations of earlier issuers)
        Map<String, ListEventListener> cacheEventListeners = getCacheEventListeners();

        Map<String, JwtDecoder> map = HashMap.newHashMap(jwkSources.size() * 4);
        List<AutoCloseable> resources = new ArrayList<>();

        for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {
            JWKSource jwkSource = entry.getValue();

            DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.Family.SIGNATURE, jwkSource);
            jwtProcessor.setJWSKeySelector(keySelector);

            NimbusJwtDecoder nimbusJwtDecoder = new NimbusJwtDecoder(jwtProcessor);
            DelegatingOAuth2TokenValidator<Jwt> validators = getJwtValidators(entry.getKey());
            nimbusJwtDecoder.setJwtValidator(validators);

            JwtDecoder decoder = nimbusJwtDecoder;

            ListEventListener eventListener = cacheEventListeners.get(entry.getKey());
            if (eventListener != null) {
                JwtDecoderCacheProperties cacheProperties = decodedJwtCacheIssuers.get(entry.getKey());
                DecodedJwtCacheJwtDecoder cachedDecoder = new DecodedJwtCacheJwtDecoder(entry.getKey(), decoder, validators, cacheProperties.getCleanupInterval() * 1000L, cacheProperties.getSize(), cacheProperties.getMode());
                cachedDecoder.scheduleCleanup();
                DecodedJwtCacheJwkEventListener cacheEventListener = new DecodedJwtCacheJwkEventListener(cachedDecoder);
                eventListener.addEventListener(cacheEventListener);
                // the JWK source outlives the decoders (i.e. when a custom ClosableJwtDecoders bean is rebuilt), so deregister on close
                resources.add(() -> eventListener.removeEventListener(cacheEventListener));
                decoder = cachedDecoder;
            }

            map.put(entry.getKey(), decoder);
        }

        return new ClosableJwtDecoders(map, resources);
    }

    /**
     * @return the JWK event listener of each issuer which has the decoded JWT cache enabled
     * @throws IllegalStateException if an issuer with the cache enabled has no JWK event listener
     */
    private Map<String, ListEventListener> getCacheEventListeners() {
        Map<String, ListEventListener> cacheEventListeners = new HashMap<>();
        if (decodedJwtCacheIssuers != null) {
            for (String issuer : jwkSources.keySet()) {
                if (decodedJwtCacheIssuers.get(issuer) != null) {
                    ListEventListener eventListener = jwkEventListeners != null ? jwkEventListeners.get(issuer) : null;
                    if (eventListener == null) {
                        // the cache must follow the JWK set (key rotation, outage); without events it would never be updated
                        throw new IllegalStateException("Decoded JWT cache is enabled for issuer '" + issuer + "', but no JWK event listener was provided for it; see " + ClosableJwtDecodersBuilder.class.getSimpleName() + ".withJwkEventListeners(..)");
                    }
                    cacheEventListeners.put(issuer, eventListener);
                }
            }
        }
        return cacheEventListeners;
    }

    private DelegatingOAuth2TokenValidator<Jwt> getJwtValidators(String issuer) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtIssuerValidator(issuer));
        validators.addAll(jwtValidators);
        return new DelegatingOAuth2TokenValidator<>(validators);
    }
}
