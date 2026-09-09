package org.entur.jwt.spring.decode.cache;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
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
import java.util.Date;
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
        // kid -> full JWK representation, so that any refresh which changes key
        // selection-relevant metadata while keeping the same kid is detected
        protected final Map<String, Map<String, Object>> keyRepresentations;
        protected final int maxCacheSize;
        protected final OAuth2TokenValidator<Jwt> jwtValidator;

        protected Cache(Map<String, Map<String, Object>> keyRepresentations, int maxCacheSize, OAuth2TokenValidator<Jwt> jwtValidator) {
            // should be immediately visible to all threads
            // so the add method can never add anything with the wrong key id
            this.keyRepresentations = Map.copyOf(keyRepresentations);
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
            if(kid != null && keyRepresentations.containsKey(kid)) {
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

        public boolean hasSameKeys(Map<String, Map<String, Object>> keyRepresentations) {
            return this.keyRepresentations.equals(keyRepresentations);
        }

        public void add(Cache cache) {
            for (Map.Entry<String, Jwt> entry : cache.map.entrySet()) {
                Jwt value = entry.getValue();
                if(value != null) {
                    String kid = (String) value.getHeaders().get("kid");
                    // only migrate entries whose key is still present with the exact same
                    // representation; a kid re-used for a rotated/different key
                    // must not carry over previously cached/validated JWTs
                    Map<String, Object> previousRepresentation = cache.keyRepresentations.get(kid);
                    Map<String, Object> currentRepresentation = keyRepresentations.get(kid);
                    if(currentRepresentation != null && currentRepresentation.equals(previousRepresentation)) {
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

    private static @NonNull Map<String, Map<String, Object>> getKeyRepresentations(JWKSet jwtSet) {
        Map<String, Map<String, Object>> keyRepresentations = new HashMap<>(jwtSet.getKeys().size() * 2);
        Date now = new Date();
        for (JWK key : jwtSet.getKeys()) {
            String keyId = key.getKeyID();
            if (keyId == null || keyId.isEmpty()) {
                continue;
            }

            // exclude keys outside their own "nbf"/"exp" validity window (if set);
            // such a key must not be treated as an active signing key, so any JWT
            // referencing its kid is neither cached nor kept in the cache
            Date notBefore = key.getNotBeforeTime();
            if (notBefore != null && notBefore.after(now)) {
                continue;
            }
            Date expirationTime = key.getExpirationTime();
            if (expirationTime != null && expirationTime.before(now)) {
                continue;
            }

            keyRepresentations.put(keyId, Map.copyOf(key.toJSONObject()));
        }
        return keyRepresentations;
    }

    @Override
    public void notify(Event event) {
        if(event instanceof CachingJWKSetSource.RefreshInitiatedEvent<?>) {
            // do nothing
        } else if(event instanceof CachingJWKSetSource.RefreshCompletedEvent<?>) {
            CachingJWKSetSource.RefreshCompletedEvent refreshCompletedEvent = (CachingJWKSetSource.RefreshCompletedEvent) event;

            Cache cache = this.cache; // defensive copy
            Map<String, Map<String, Object>> keyRepresentations = getKeyRepresentations(refreshCompletedEvent.getJWKSet());

            // compare the full JWK representation for each kid, not just key id or
            // RFC 7638 thumbprint, so metadata changes affecting key selection also
            // invalidate previously cached JWTs.
            if(cache.hasSameKeys(keyRepresentations)) {
                // do nothing
            } else {
                // create a new cache
                Cache nextCache = new Cache(keyRepresentations, maxCacheSize, jwtValidator);
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
