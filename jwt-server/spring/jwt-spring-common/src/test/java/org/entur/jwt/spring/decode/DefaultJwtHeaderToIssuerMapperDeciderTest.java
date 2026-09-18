package org.entur.jwt.spring.decode;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultJwtHeaderToIssuerMapperDeciderTest {

    private Jwt jwtWithHeaders(Map<String, Object> headers) {
        Map<String, Object> claims = Collections.singletonMap("sub", "subject");
        return new Jwt("token", Instant.now(), Instant.now().plusSeconds(60), headers, claims);
    }

    @Test
    void acceptsWhenKidIsNonEmptyString() {
        DefaultJwtHeaderToIssuerMapperDecider decider = new DefaultJwtHeaderToIssuerMapperDecider();
        assertTrue(decider.apply(jwtWithHeaders(Map.of("alg", "RS256", "kid", "key-1"))));
    }

    @Test
    void rejectsWhenKidIsEmptyString() {
        DefaultJwtHeaderToIssuerMapperDecider decider = new DefaultJwtHeaderToIssuerMapperDecider();
        assertFalse(decider.apply(jwtWithHeaders(Map.of("alg", "RS256", "kid", ""))));
    }

    @Test
    void rejectsWhenKidMissing() {
        DefaultJwtHeaderToIssuerMapperDecider decider = new DefaultJwtHeaderToIssuerMapperDecider();
        assertFalse(decider.apply(jwtWithHeaders(Collections.singletonMap("alg", "RS256"))));
    }

    @Test
    void rejectsWhenKidIsNotString() {
        DefaultJwtHeaderToIssuerMapperDecider decider = new DefaultJwtHeaderToIssuerMapperDecider();
        assertFalse(decider.apply(jwtWithHeaders(Map.of("alg", "RS256", "kid", 123))));
    }
}
