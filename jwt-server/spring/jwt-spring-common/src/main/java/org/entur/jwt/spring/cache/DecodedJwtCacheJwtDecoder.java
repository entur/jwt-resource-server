package org.entur.jwt.spring.cache;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Caching of validated JWTs.
 *
 * If used, make sure to proactively update JWKs somehow.
 *
 */

public class DecodedJwtCacheJwtDecoder implements JwtDecoder, EventListener {

    private static final String DECODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to decode the Jwt: %s";

    protected final JwtDecoder delegate;
    protected final OAuth2TokenValidator<Jwt> jwtValidator;

    protected Map<String, Jwt> cache = new ConcurrentHashMap<>();

    protected volatile boolean writeEnabled = false;
    protected volatile boolean readEnabled = false;

    public  DecodedJwtCacheJwtDecoder(JwtDecoder delegate, OAuth2TokenValidator<Jwt> jwtValidators) {
        this.delegate = delegate;
        this.jwtValidator = jwtValidators;
    }

    @Override
    public Jwt decode(String token) throws JwtException {

        if(readEnabled) {
            Jwt cachedJwt = cache.get(token);
            if (cachedJwt != null) {
                return validateJwt(cachedJwt);
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

    public void refresh(JWKSet jwtSet) {
        Set<String> keyIds = new HashSet<>(jwtSet.getKeys().size());
        for (JWK key : jwtSet.getKeys()) {
            keyIds.add(key.getKeyID());
        }

        // remove unknown keys
        for (Map.Entry<String, Jwt> entry : cache.entrySet()) {
            Jwt value = entry.getValue();
            if(value != null) {
                if (!keyIds.contains(value.getHeaders().get("kid"))) {
                    cache.remove(entry.getKey());
                }
            }
        }

        // remove no longer valid jwts
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
            refresh(refreshCompletedEvent.getJWKSet());

            CachingJWKSetSource source = (CachingJWKSetSource) refreshCompletedEvent.getSource();
            source.getCacheRefreshTimeout()

            writeEnabled = true;
            readEnabled = true;
        } else if(event instanceof CachingJWKSetSource.UnableToRefreshEvent<?>) {
            readEnabled = false;
            // write only happens if approved by regular flow
        } else if(event instanceof CachingJWKSetSource.RefreshTimedOutEvent<?>) {
            readEnabled = false;
            // write only happens if approved by regular flow
        }
    }
}
