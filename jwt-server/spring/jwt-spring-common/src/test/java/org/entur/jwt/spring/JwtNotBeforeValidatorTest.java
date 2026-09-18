package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtNotBeforeValidatorTest {

    private Jwt jwtNotBefore(Instant notBefore) {
        Map<String, Object> headers = Collections.singletonMap("alg", "none");
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "subject");
        if (notBefore != null) {
            claims.put("nbf", notBefore.getEpochSecond());
        }
        return new Jwt("token", Instant.now(), Instant.now().plusSeconds(3600), headers, claims);
    }

    @Test
    void succeedsWhenNoNotBeforeClaim() {
        JwtNotBeforeValidator validator = new JwtNotBeforeValidator(Duration.ZERO);
        OAuth2TokenValidatorResult result = validator.validate(jwtNotBefore(null));
        assertFalse(result.hasErrors());
    }

    @Test
    void succeedsWhenNotBeforeHasPassed() {
        JwtNotBeforeValidator validator = new JwtNotBeforeValidator(Duration.ZERO);
        OAuth2TokenValidatorResult result = validator.validate(jwtNotBefore(Instant.now().minusSeconds(60)));
        assertFalse(result.hasErrors());
    }

    @Test
    void failsWhenNotBeforeInFuture() {
        JwtNotBeforeValidator validator = new JwtNotBeforeValidator(Duration.ZERO);
        Clock fixedClock = Clock.fixed(Instant.now(), ZoneOffset.UTC);
        validator.setClock(fixedClock);

        OAuth2TokenValidatorResult result = validator.validate(jwtNotBefore(Instant.now().plusSeconds(120)));
        assertTrue(result.hasErrors());
    }

    @Test
    void clockSkewAllowsGracePeriod() {
        JwtNotBeforeValidator validator = new JwtNotBeforeValidator(Duration.ofSeconds(120));
        Clock fixedClock = Clock.fixed(Instant.now(), ZoneOffset.UTC);
        validator.setClock(fixedClock);

        OAuth2TokenValidatorResult result = validator.validate(jwtNotBefore(Instant.now().plusSeconds(60)));
        assertFalse(result.hasErrors());
    }

    @Test
    void nullClockSkewThrows() {
        assertThrows(IllegalArgumentException.class, () -> new JwtNotBeforeValidator(null));
    }

    @Test
    void nullClockThrows() {
        JwtNotBeforeValidator validator = new JwtNotBeforeValidator(Duration.ZERO);
        assertThrows(IllegalArgumentException.class, () -> validator.setClock(null));
    }

    @Test
    void nullJwtThrows() {
        JwtNotBeforeValidator validator = new JwtNotBeforeValidator(Duration.ZERO);
        assertThrows(IllegalArgumentException.class, () -> validator.validate(null));
    }
}
