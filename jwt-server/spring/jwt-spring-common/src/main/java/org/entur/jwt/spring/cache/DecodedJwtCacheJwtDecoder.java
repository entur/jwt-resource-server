package org.entur.jwt.spring.cache;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;
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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
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

    protected final JwtDecoder delegate;
    protected final OAuth2TokenValidator<Jwt> jwtValidator;

    protected ConcurrentHashMap<String, Jwt> cache = new ConcurrentHashMap<>();

    protected Set<String> keyIds = Collections.emptySet();

    protected volatile boolean writeEnabled = false;
    protected volatile boolean readEnabled = false;

    protected long cleanupInterval;

    public  DecodedJwtCacheJwtDecoder(JwtDecoder delegate, OAuth2TokenValidator<Jwt> jwtValidators, long cleanupInterval) {
        this.delegate = delegate;
        this.jwtValidator = jwtValidators;
        this.cleanupInterval = cleanupInterval;
    }

    public void scheduleCleanup() {
        scheduledExecutorService.scheduleWithFixedDelay(() -> {
            if(LOGGER.isDebugEnabled()) LOGGER.debug("Cleaning cache");
            try {
                // should not be any, but a catch all mechanism
                cleanCacheForJwtsWithUnknownKeyIds();

                cleanCacheForInvalidJwts();
            } catch (Throwable e) {
                // ignore, will be handled by regular flow
                LOGGER.warn("Problem cleaning cache", e);
            }
        }, cleanupInterval, cleanupInterval, TimeUnit.MILLISECONDS);
    }

    @Override
    public Jwt decode(String token) throws JwtException {

        if(readEnabled) {
            Jwt cachedJwt = cache.get(token);
            if (cachedJwt != null) {
                if(keyIds.contains(cachedJwt.getHeaders().get("kid"))) {
                    return validateJwt(cachedJwt);
                }
            }
        }

        Jwt jwt = delegate.decode(token);

        if(writeEnabled) {
            cache.put(token, jwt);
        }

        return jwt;
    }

    protected Jwt validateJwt(Jwt jwt) {
        OAuth2TokenValidatorResult result = jwtValidator.validate(jwt);
        if (result.hasErrors()) {
            cache.remove(jwt.getTokenValue());

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

    public void clear() {
        cache.clear();
    }

    public void setKeyIds(JWKSet jwtSet) {
        Set<String> keyIds = new HashSet<>(jwtSet.getKeys().size());
        for (JWK key : jwtSet.getKeys()) {
            keyIds.add(key.getKeyID());
        }
        this.keyIds = keyIds;
    }

    public void cleanCacheForJwtsWithUnknownKeyIds() {
        // remove unknown keys
        for (Map.Entry<String, Jwt> entry : cache.entrySet()) {
            Jwt value = entry.getValue();
            if(value != null) {
                if (!keyIds.contains(value.getHeaders().get("kid"))) {
                    cache.remove(entry.getKey());
                }
            }
        }

    }

    protected void cleanCacheForInvalidJwts() {
        // remove no longer valid JWTs. Typically they expire by time.
        for (Map.Entry<String, Jwt> entry : cache.entrySet()) {
            Jwt value = entry.getValue();
            if(value != null) {
                OAuth2TokenValidatorResult result = jwtValidator.validate(value);
                if (result.hasErrors()) {
                    cache.remove(entry.getKey());
                }
            }
        }
    }

    @Override
    public void notify(Event event) {
        if(event instanceof CachingJWKSetSource.RefreshInitiatedEvent<?>) {
            writeEnabled = false;
        } else if(event instanceof CachingJWKSetSource.RefreshCompletedEvent<?>) {
            CachingJWKSetSource.RefreshCompletedEvent refreshCompletedEvent = (CachingJWKSetSource.RefreshCompletedEvent) event;
            setKeyIds(refreshCompletedEvent.getJWKSet());

            cleanCacheForJwtsWithUnknownKeyIds();
            cleanCacheForInvalidJwts();

            readEnabled = true;
            writeEnabled = true;
        } else if(event instanceof CachingJWKSetSource.UnableToRefreshEvent<?>) {
            readEnabled = false;
            // there might still some time left until no JWKs are cached anymore
        } else if(event instanceof CachingJWKSetSource.RefreshTimedOutEvent<?>) {
            readEnabled = false;
            // there might still some time left until no JWKs are cached anymore
        }
    }

    public void close() {
        scheduledExecutorService.shutdownNow();
    }
}
