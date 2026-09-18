package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DataTypesClaimOauth2TokenValidatorTest {

    private Jwt jwtWithClaims(Map<String, Object> extraClaims) {
        Map<String, Object> headers = Collections.singletonMap("alg", "none");
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "subject");
        claims.putAll(extraClaims);
        return new Jwt("token", Instant.now(), Instant.now().plusSeconds(60), headers, claims);
    }

    @Test
    void succeedsWhenClaimHasExpectedType() {
        Map<String, Class<?>> types = Collections.singletonMap("scope", String.class);
        DataTypesClaimOauth2TokenValidator validator = new DataTypesClaimOauth2TokenValidator(types);

        OAuth2TokenValidatorResult result = validator.validate(jwtWithClaims(Collections.singletonMap("scope", "read")));
        assertFalse(result.hasErrors());
    }

    @Test
    void failsWhenClaimIsMissing() {
        Map<String, Class<?>> types = Collections.singletonMap("scope", String.class);
        DataTypesClaimOauth2TokenValidator validator = new DataTypesClaimOauth2TokenValidator(types);

        OAuth2TokenValidatorResult result = validator.validate(jwtWithClaims(Collections.emptyMap()));
        assertTrue(result.hasErrors());
    }

    @Test
    void failsWhenClaimHasWrongType() {
        Map<String, Class<?>> types = Collections.singletonMap("scope", String.class);
        DataTypesClaimOauth2TokenValidator validator = new DataTypesClaimOauth2TokenValidator(types);

        OAuth2TokenValidatorResult result = validator.validate(jwtWithClaims(Collections.singletonMap("scope", 123)));
        assertTrue(result.hasErrors());
    }
}
