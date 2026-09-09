package org.entur.jwt.spring.decode.cache;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.util.StringUtils;

import java.io.Closeable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Caching of validated JWTs.
 *
 * If used, make sure to proactively update JWKs somehow.
 *
 */
public class DecodedJwtCacheJwtDecoder implements JwtDecoder, EventListener, Closeable {

    private static final String DECODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to decode the Jwt: %s";

    private static final Logger LOGGER = LoggerFactory.getLogger(DecodedJwtCacheJwtDecoder.class);

    public static ScheduledExecutorService createDefaultScheduledExecutorService() {
        return Executors.newSingleThreadScheduledExecutor();
    }

    // created lazily so instances with cleanup disabled (cleanupInterval <= 0) don't spin up an unused background thread
    protected volatile ScheduledExecutorService scheduledExecutorService;

    protected static class Cache {
        protected final ConcurrentHashMap<String, Jwt> map;
        // kid -> RFC 7638 JWK thumbprint, so that a key whose material changed while
        // keeping the same kid is still detected as a different key (see below)
        protected final Map<String, Base64URL> keyFingerprints;
        protected final int maxCacheSize;
        protected final OAuth2TokenValidator<Jwt> jwtValidator;

        protected Cache(Map<String, Base64URL> keyFingerprints, int maxCacheSize, OAuth2TokenValidator<Jwt> jwtValidator) {
            // should be immediately visible to all threads
            // so the add method can never add anything with the wrong key id
            this.keyFingerprints = Map.copyOf(keyFingerprints);
            if(maxCacheSize == -1) {
                this.map = new ConcurrentHashMap<>();
                this.maxCacheSize = Integer.MAX_VALUE;
            } else {
                this.map = new ConcurrentHashMap<>(2 * maxCacheSize);
                this.maxCacheSize = maxCacheSize;
            }
            this.jwtValidator = jwtValidator;
        }

        public void add(String token, Jwt jwt) {
            // the size check is not atomic with the put, but it is good enough for this use case.
            if(map.size() >= maxCacheSize) {
                return;
            }

            String kid = (String)jwt.getHeaders().get("kid");
            if(kid != null && keyFingerprints.containsKey(kid)) {
                map.put(token, jwt);
            }
        }

        public Jwt get(String token) {
            return map.get(token);
        }

        public void remove(String token) {
            map.remove(token);
        }

        public void clear() {
            map.clear();
        }

        protected int cleanInvalidJwts() {
            int count = 0;
            // remove no longer valid JWTs. Typically they expire by time.
            for (Map.Entry<String, Jwt> entry : map.entrySet()) {
                Jwt value = entry.getValue();
                if(value != null) {
                    OAuth2TokenValidatorResult result = jwtValidator.validate(value);
                    if (result.hasErrors()) {
                        map.remove(entry.getKey());
                        count++;
                    }
                }
            }
            return count;
        }

        public boolean hasSameKeys(Map<String, Base64URL> keyFingerprints) {
            return this.keyFingerprints.equals(keyFingerprints);
        }

        public void add(Cache cache) {
            for (Map.Entry<String, Jwt> entry : cache.map.entrySet()) {
                Jwt value = entry.getValue();
                if(value != null) {
                    String kid = (String) value.getHeaders().get("kid");
                    // only migrate entries whose key is still present with the exact same
                    // material (fingerprint); a kid re-used for a rotated/different key
                    // must not carry over previously cached/validated JWTs
                    Base64URL previousFingerprint = cache.keyFingerprints.get(kid);
                    Base64URL currentFingerprint = keyFingerprints.get(kid);
                    if(currentFingerprint != null && currentFingerprint.equals(previousFingerprint)) {
                        add(entry.getKey(), value); // also re-filters on key id
                    }
                }
            }
        }

        public boolean isEmpty() {
            return map.isEmpty();
        }

        public int size() {
            return map.size();
        }
    }

    protected final JwtDecoder jwtValidatingDecoder;
    protected final OAuth2TokenValidator<Jwt> jwtValidator;

    protected final long cleanupInterval;
    protected final int maxCacheSize;

    protected volatile Cache cache;

    public DecodedJwtCacheJwtDecoder(JwtDecoder jwtValidatingDecoder, OAuth2TokenValidator<Jwt> jwtValidators, long cleanupIntervalMillis, int maxCacheSize) {
        this.jwtValidatingDecoder = jwtValidatingDecoder;
        this.jwtValidator = jwtValidators;
        this.cleanupInterval = cleanupIntervalMillis;
        this.maxCacheSize = maxCacheSize;

        cache = new Cache(Collections.emptyMap(), 0, jwtValidator);
    }

    public synchronized void scheduleCleanup() {
        if (cleanupInterval <= 0) {
            return;
        }
        if (scheduledExecutorService == null) {
            scheduledExecutorService = createDefaultScheduledExecutorService();
        }
        scheduledExecutorService.scheduleWithFixedDelay(this::cleanup,
                cleanupInterval, cleanupInterval, TimeUnit.MILLISECONDS);
    }

    public void cleanup() {
        if(!cache.isEmpty()) {
            try {
                // avoid memory leaks due to stagnant JWTs
                int cleaned = cache.cleanInvalidJwts();
                if(cleaned > 0) {
                    if (LOGGER.isDebugEnabled()) LOGGER.debug("Cleaned {} invalid JWTs from cache, now have {}", cleaned, cache.map.size());
                }
            } catch (Throwable e) {
                // ignore, will be handled by regular flow
                LOGGER.warn("Problem cleaning cache", e);
            }
        }
    }

    @Override
    public Jwt decode(String token) throws JwtException {

        Cache c = this.cache; // defensive copy

        Jwt cachedJwt = c.get(token);
        if (cachedJwt != null) {
            // we have a cache hit, is it still valid?
            return validateJwt(cachedJwt, c);
        }

        Jwt jwt = jwtValidatingDecoder.decode(token); // also validates
        c.add(token, jwt); // only adds if the keyid is known, otherwise ignored

        // implementation note: if the first JWT also refreshes that JWKs, it will not be cached itself
        // since that will create a new cache instance (which is not the same as the local copy)

        return jwt;
    }

    protected Jwt validateJwt(Jwt jwt, Cache c) {
        OAuth2TokenValidatorResult result = jwtValidator.validate(jwt);
        if (result.hasErrors()) {
            c.remove(jwt.getTokenValue());

            Collection<OAuth2Error> errors = result.getErrors();
            String validationErrorString = getJwtValidationExceptionMessage(errors);
            throw new JwtValidationException(validationErrorString, errors);
        }
        return jwt;
    }

    protected String getJwtValidationExceptionMessage(Collection<OAuth2Error> errors) {
        for (OAuth2Error oAuth2Error : errors) {
            if (StringUtils.hasLength(oAuth2Error.getDescription())) {
                return String.format(DECODING_ERROR_MESSAGE_TEMPLATE, oAuth2Error.getDescription());
            }
        }
        return "Unable to validate Jwt";
    }

    // clears tokens, not key ids
    public void clear() {
        cache.clear();
    }

    private static @NonNull Map<String, Base64URL> getKeyFingerprints(JWKSet jwtSet) {
        Map<String, Base64URL> keyFingerprints = new HashMap<>(jwtSet.getKeys().size() * 2);
        for (JWK key : jwtSet.getKeys()) {
            String keyId = key.getKeyID();
            if (keyId != null && !keyId.isEmpty()) {
                try {
                    // RFC 7638 thumbprint of the key material itself (not metadata such as
                    // "use"/"key_ops"), so that a rotated key which keeps the same kid --
                    // as is known to happen with e.g. Active Directory Federation Services (ADFS),
                    // which derives the kid from the certificate thumbprint but has in practice
                    // been observed to reuse identifiers across certificate renewals -- is still
                    // detected as a different key rather than assumed unchanged.
                    keyFingerprints.put(keyId, key.computeThumbprint());
                } catch (JOSEException e) {
                    // key material could not be fingerprinted; do not trust this kid as unchanged,
                    // any cached JWTs referencing it are dropped by not being retained here
                    LOGGER.warn("Unable to compute thumbprint for key with id {}", keyId, e);
                }
            }
        }
        return keyFingerprints;
    }

    @Override
    public void notify(Event event) {
        if(event instanceof CachingJWKSetSource.RefreshInitiatedEvent<?>) {
            // do nothing
        } else if(event instanceof CachingJWKSetSource.RefreshCompletedEvent<?>) {
            CachingJWKSetSource.RefreshCompletedEvent refreshCompletedEvent = (CachingJWKSetSource.RefreshCompletedEvent) event;

            Cache cache = this.cache; // defensive copy
            Map<String, Base64URL> keyFingerprints = getKeyFingerprints(refreshCompletedEvent.getJWKSet());

            // compare kid + key material (thumbprint), not just kid, since some IdPs
            // (see getKeyFingerprints) are known to reuse the same kid across rotations
            if(cache.hasSameKeys(keyFingerprints)) {
                // do nothing
            } else {
                // create a new cache
                Cache nextCache = new Cache(keyFingerprints, maxCacheSize, jwtValidator);
                // copy still-valid JWTs from the old cache to the new cache
                nextCache.add(cache);
                this.cache = nextCache;
            }
        } else if(event instanceof CachingJWKSetSource.UnableToRefreshEvent<?>) {
            // do nothing
        } else if(event instanceof CachingJWKSetSource.RefreshTimedOutEvent<?>) {
            // do nothing
        }
    }

    public void close() {
        ScheduledExecutorService executor = scheduledExecutorService; // defensive copy
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    public int getSize() {
        return cache.size();
    }
}
