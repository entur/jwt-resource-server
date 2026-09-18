package org.entur.jwt.spring;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeycloakJwtAuthorityEnricherTest {

    private Jwt jwtWithResourceAccess(Map<String, Object> resourceAccess) {
        Map<String, Object> headers = Collections.singletonMap("alg", "none");
        Map<String, Object> claims = resourceAccess == null
                ? Collections.singletonMap("sub", "subject")
                : Map.of("sub", "subject", "resource_access", resourceAccess);
        return new Jwt("token", Instant.now(), Instant.now().plusSeconds(60), headers, claims);
    }

    @Test
    void enrichesWithRolesFromResourceAccess() {
        KeycloakJwtAuthorityEnricher enricher = new KeycloakJwtAuthorityEnricher();

        Map<String, Object> resourceAccess = Map.of(
                "my-test-client", Map.of("roles", List.of("my-new-client-role")),
                "account", Map.of("roles", List.of("manage-account"))
        );

        Collection<GrantedAuthority> current = new ArrayList<>();
        enricher.enrich(current, jwtWithResourceAccess(resourceAccess));

        Collection<String> authorityNames = current.stream().map(GrantedAuthority::getAuthority).toList();
        assertTrue(authorityNames.contains("ROLE_my-new-client-role"));
        // "account" entries are intentionally skipped
        assertEquals(1, current.size());
    }

    @Test
    void doesNotDuplicateExistingRolePrefix() {
        KeycloakJwtAuthorityEnricher enricher = new KeycloakJwtAuthorityEnricher();

        Map<String, Object> resourceAccess = Map.of(
                "my-test-client", Map.of("roles", List.of("ROLE_already-prefixed"))
        );

        Collection<GrantedAuthority> current = new ArrayList<>();
        enricher.enrich(current, jwtWithResourceAccess(resourceAccess));

        Collection<String> authorityNames = current.stream().map(GrantedAuthority::getAuthority).toList();
        assertTrue(authorityNames.contains("ROLE_already-prefixed"));
        assertEquals(1, current.size());
    }

    @Test
    void doesNothingWhenNoResourceAccessClaim() {
        KeycloakJwtAuthorityEnricher enricher = new KeycloakJwtAuthorityEnricher();

        Collection<GrantedAuthority> current = new ArrayList<>();
        enricher.enrich(current, jwtWithResourceAccess(null));

        assertTrue(current.isEmpty());
    }
}
