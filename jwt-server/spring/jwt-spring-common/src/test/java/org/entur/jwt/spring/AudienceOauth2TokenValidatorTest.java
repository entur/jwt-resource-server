package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AudienceOauth2TokenValidatorTest {

    private Jwt jwtWithAudience(List<String> audience) {
        Map<String, Object> headers = Collections.singletonMap("alg", "none");
        Map<String, Object> claims = audience == null
                ? Collections.singletonMap("sub", "subject")
                : Map.of("sub", "subject", "aud", audience);
        return new Jwt("token", Instant.now(), Instant.now().plusSeconds(60), headers, claims);
    }

    @Test
    void succeedsWhenAudienceMatches() {
        AudienceOauth2TokenValidator validator = new AudienceOauth2TokenValidator(Arrays.asList("aud1", "aud2"));
        OAuth2TokenValidatorResult result = validator.validate(jwtWithAudience(Arrays.asList("aud2")));
        assertFalse(result.hasErrors());
    }

    @Test
    void failsWhenAudienceDoesNotMatch() {
        AudienceOauth2TokenValidator validator = new AudienceOauth2TokenValidator(Arrays.asList("aud1"));
        OAuth2TokenValidatorResult result = validator.validate(jwtWithAudience(Arrays.asList("other")));
        assertTrue(result.hasErrors());
    }

    @Test
    void failsWhenTokenHasNoAudience() {
        AudienceOauth2TokenValidator validator = new AudienceOauth2TokenValidator(Arrays.asList("aud1"));
        OAuth2TokenValidatorResult result = validator.validate(jwtWithAudience(null));
        assertTrue(result.hasErrors());
    }

    @Test
    void acceptsSetConstructor() {
        AudienceOauth2TokenValidator validator = new AudienceOauth2TokenValidator(Collections.singleton("aud1"));
        OAuth2TokenValidatorResult result = validator.validate(jwtWithAudience(Arrays.asList("aud1")));
        assertFalse(result.hasErrors());
    }
}
