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

class Auth0JwtAuthorityEnricherTest {

    private Jwt jwtWithPermissions(List<String> permissions) {
        Map<String, Object> headers = Collections.singletonMap("alg", "none");
        Map<String, Object> claims = permissions == null
                ? Collections.singletonMap("sub", "subject")
                : Map.of("sub", "subject", "permissions", permissions);
        return new Jwt("token", Instant.now(), Instant.now().plusSeconds(60), headers, claims);
    }

    @Test
    void enrichesWithPermissionAuthorities() {
        Auth0JwtAuthorityEnricher enricher = new Auth0JwtAuthorityEnricher();

        Collection<GrantedAuthority> current = new ArrayList<>();
        enricher.enrich(current, jwtWithPermissions(List.of("read:things", "write:things")));

        Collection<String> authorityNames = current.stream().map(GrantedAuthority::getAuthority).toList();
        assertTrue(authorityNames.contains("read:things"));
        assertTrue(authorityNames.contains("write:things"));
        assertEquals(2, current.size());
    }

    @Test
    void doesNothingWhenNoPermissionsClaim() {
        Auth0JwtAuthorityEnricher enricher = new Auth0JwtAuthorityEnricher();

        Collection<GrantedAuthority> current = new ArrayList<>();
        enricher.enrich(current, jwtWithPermissions(null));

        assertTrue(current.isEmpty());
    }

    @Test
    void doesNothingWhenPermissionsEmpty() {
        Auth0JwtAuthorityEnricher enricher = new Auth0JwtAuthorityEnricher();

        Collection<GrantedAuthority> current = new ArrayList<>();
        enricher.enrich(current, jwtWithPermissions(Collections.emptyList()));

        assertTrue(current.isEmpty());
    }
}
