package org.entur.jwt.spring.cache;

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
import java.util.*;
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

    protected ScheduledExecutorService scheduledExecutorService = createDefaultScheduledExecutorService();

    protected class Cache {
        protected final ConcurrentHashMap<String, Jwt> cache;
        protected final Set<String> keyIds;

        protected Cache(Set<String> keyIds, ConcurrentHashMap<String, Jwt> map) {
            // should be immediately visible to all threads
            // so the add method can never add anything with the wrong key id
            this.keyIds = Set.copyOf(keyIds);
            this.cache = map;
        }

        protected Cache(Set<String> keyIds) {
            this(keyIds, new ConcurrentHashMap<>());
        }

        public void add(String token, Jwt jwt) {
            if(cache.size() >= maxCacheSize) {
                return;
            }

            String kid = (String)jwt.getHeaders().get("kid");
            if(kid != null && keyIds.contains(kid)) {
                cache.put(token, jwt);
            }
        }

        public Jwt get(String token) {
            return cache.get(token);
        }

        public boolean containsKeyId(String kid) {
            return keyIds.contains(kid);
        }

        public void remove(String token) {
            cache.remove(token);
        }

        public void clear() {
            cache.clear();
        }

        protected int cleanInvalidJwts() {
            int count = 0;
            // remove no longer valid JWTs. Typically they expire by time.
            for (Map.Entry<String, Jwt> entry : cache.entrySet()) {
                Jwt value = entry.getValue();
                if(value != null) {
                    OAuth2TokenValidatorResult result = jwtValidator.validate(value);
                    if (result.hasErrors()) {
                        cache.remove(entry.getKey());
                        count++;
                    }
                }
            }
            return count;
        }

        public boolean hasSameKeyIds(Set<String> keyIds) {
            return this.keyIds.equals(keyIds);
        }

        public void add(Cache cache) {
            for (Map.Entry<String, Jwt> entry : cache.cache.entrySet()) {
                Jwt value = entry.getValue();
                if(value != null) {
                    add(entry.getKey(), value); // filters on key id
                }
            }
        }

        public boolean isEmpty() {
            return cache.isEmpty();
        }
    }

    protected final JwtDecoder jwtValidatingDecoder;
    protected final OAuth2TokenValidator<Jwt> jwtValidator;

    protected volatile Cache cache = new Cache(Collections.emptySet());

    protected final long cleanupInterval;
    protected final int maxCacheSize;

    public DecodedJwtCacheJwtDecoder(JwtDecoder jwtValidatingDecoder, OAuth2TokenValidator<Jwt> jwtValidators, long cleanupIntervalMillis, int maxCacheSize) {
        this.jwtValidatingDecoder = jwtValidatingDecoder;
        this.jwtValidator = jwtValidators;
        this.cleanupInterval = cleanupIntervalMillis;
        this.maxCacheSize = maxCacheSize == -1 ? Integer.MAX_VALUE : maxCacheSize;
    }

    public void scheduleCleanup() {
        scheduledExecutorService.scheduleWithFixedDelay(() -> {
            if(!cache.isEmpty()) {
                if (LOGGER.isDebugEnabled()) LOGGER.debug("Cleaning cache of size {}", cache.cache.size());
                try {
                    // avoid memory leaks due to stagnant JWTs
                    int cleaned = cache.cleanInvalidJwts();
                    if(cleaned > 0) {
                        if (LOGGER.isDebugEnabled()) LOGGER.debug("Cleaned {} invalid JWTs from cache, now have {}", cleaned, cache.cache.size());
                    }
                } catch (Throwable e) {
                    // ignore, will be handled by regular flow
                    LOGGER.warn("Problem cleaning cache", e);
                }
            }
        }, cleanupInterval, cleanupInterval, TimeUnit.MILLISECONDS);
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

    private static @NonNull Set<String> convert(JWKSet jwtSet) {
        Set<String> keyIds = new HashSet<>(jwtSet.getKeys().size());
        for (JWK key : jwtSet.getKeys()) {
            String keyId = key.getKeyID();
            if (keyId != null) {
                keyIds.add(keyId);
            }
        }
        return keyIds;
    }

    @Override
    public void notify(Event event) {
        if(event instanceof CachingJWKSetSource.RefreshInitiatedEvent<?>) {
            // do nothing
        } else if(event instanceof CachingJWKSetSource.RefreshCompletedEvent<?>) {
            CachingJWKSetSource.RefreshCompletedEvent refreshCompletedEvent = (CachingJWKSetSource.RefreshCompletedEvent) event;

            Cache cache = this.cache;
            Set<String> keyIds = convert(refreshCompletedEvent.getJWKSet());
            if(cache.hasSameKeyIds(keyIds)) {
                // do nothing
            } else {
                // create a new cache
                Cache nextCache = new Cache(keyIds);
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
        scheduledExecutorService.shutdownNow();
    }
}
