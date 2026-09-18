package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

class NoopJwtAuthorityEnricherTest {

    @Test
    void doesNotModifyAuthorities() {
        NoopJwtAuthorityEnricher enricher = new NoopJwtAuthorityEnricher();

        Map<String, Object> headers = Collections.singletonMap("alg", "none");
        Map<String, Object> claims = Collections.singletonMap("sub", "subject");
        Jwt jwt = new Jwt("token", Instant.now(), Instant.now().plusSeconds(60), headers, claims);

        Collection<GrantedAuthority> current = new ArrayList<>();
        enricher.enrich(current, jwt);

        assertTrue(current.isEmpty());
    }
}
