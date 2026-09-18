package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultJwtAuthorityEnricherTest {

    private Jwt jwtWithScope(String scope) {
        Map<String, Object> headers = Collections.singletonMap("alg", "none");
        Map<String, Object> claims = Map.of("sub", "subject", "scope", scope);
        return new Jwt("token", Instant.now(), Instant.now().plusSeconds(60), headers, claims);
    }

    @Test
    void enrichesWithScopeAuthorities() {
        DefaultJwtAuthorityEnricher enricher = new DefaultJwtAuthorityEnricher();

        Collection<GrantedAuthority> current = new ArrayList<>();
        enricher.enrich(current, jwtWithScope("read write"));

        Collection<String> authorityNames = current.stream().map(GrantedAuthority::getAuthority).toList();
        assertTrue(authorityNames.contains("SCOPE_read"));
        assertTrue(authorityNames.contains("SCOPE_write"));
        assertEquals(2, current.size());
    }

    @Test
    void exposesUnderlyingConverter() {
        DefaultJwtAuthorityEnricher enricher = new DefaultJwtAuthorityEnricher();
        assertTrue(enricher.getJwtGrantedAuthoritiesConverter() != null);
    }
}
