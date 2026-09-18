package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtExpiresAtValidatorTest {

    private Jwt jwtExpiringAt(Instant expiresAt) {
        Map<String, Object> headers = Collections.singletonMap("alg", "none");
        Map<String, Object> claims = Collections.singletonMap("sub", "subject");
        return new Jwt("token", Instant.now(), expiresAt, headers, claims);
    }

    @Test
    void succeedsWhenNotExpired() {
        JwtExpiresAtValidator validator = new JwtExpiresAtValidator(Duration.ZERO);
        OAuth2TokenValidatorResult result = validator.validate(jwtExpiringAt(Instant.now().plusSeconds(60)));
        assertFalse(result.hasErrors());
    }

    @Test
    void succeedsWhenNoExpiry() {
        JwtExpiresAtValidator validator = new JwtExpiresAtValidator(Duration.ZERO);

        Map<String, Object> headers = Collections.singletonMap("alg", "none");
        Map<String, Object> claims = Collections.singletonMap("sub", "subject");
        Jwt jwt = new Jwt("token", Instant.now(), null, headers, claims);

        OAuth2TokenValidatorResult result = validator.validate(jwt);
        assertFalse(result.hasErrors());
    }

    @Test
    void failsWhenExpired() {
        JwtExpiresAtValidator validator = new JwtExpiresAtValidator(Duration.ZERO);
        Clock fixedClock = Clock.fixed(Instant.now().plusSeconds(120), ZoneOffset.UTC);
        validator.setClock(fixedClock);

        OAuth2TokenValidatorResult result = validator.validate(jwtExpiringAt(Instant.now().plusSeconds(60)));
        assertTrue(result.hasErrors());
    }

    @Test
    void clockSkewAllowsGracePeriod() {
        JwtExpiresAtValidator validator = new JwtExpiresAtValidator(Duration.ofSeconds(120));
        Clock fixedClock = Clock.fixed(Instant.now().plusSeconds(60), ZoneOffset.UTC);
        validator.setClock(fixedClock);

        OAuth2TokenValidatorResult result = validator.validate(jwtExpiringAt(Instant.now().plusSeconds(30)));
        assertFalse(result.hasErrors());
    }

    @Test
    void nullClockSkewThrows() {
        assertThrows(IllegalArgumentException.class, () -> new JwtExpiresAtValidator(null));
    }

    @Test
    void nullClockThrows() {
        JwtExpiresAtValidator validator = new JwtExpiresAtValidator(Duration.ZERO);
        assertThrows(IllegalArgumentException.class, () -> validator.setClock(null));
    }

    @Test
    void nullJwtThrows() {
        JwtExpiresAtValidator validator = new JwtExpiresAtValidator(Duration.ZERO);
        assertThrows(IllegalArgumentException.class, () -> validator.validate(null));
    }
}
