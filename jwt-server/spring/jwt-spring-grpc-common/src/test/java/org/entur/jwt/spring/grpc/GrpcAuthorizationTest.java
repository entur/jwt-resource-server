package org.entur.jwt.spring.grpc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class GrpcAuthorizationTest implements GrpcAuthorization {

    private Authentication authentication;

    @Override
    public Authentication getAuthentication() {
        return authentication;
    }

    private JwtAuthenticationToken newToken(Object audienceClaim, String... authorities) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "subject");
        if (audienceClaim != null) {
            claims.put("aud", audienceClaim);
        }

        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (String authority : authorities) {
            grantedAuthorities.add(new SimpleGrantedAuthority(authority));
        }

        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "none");

        Jwt jwt = new Jwt("credentials", Instant.EPOCH, Instant.MAX, headers, claims);

        return new JwtAuthenticationToken(jwt, grantedAuthorities);
    }

    @BeforeEach
    public void before() {
        authentication = null;
    }

    // -- getPrincial / getToken --

    @Test
    public void testGetPrincialAndTokenWithoutAuthentication() {
        assertNull(getPrincial());
        assertNull(getToken());
    }

    @Test
    public void testGetPrincialAndTokenWithJwtAuthentication() {
        JwtAuthenticationToken token = newToken(List.of("http://entur.org"), "read");
        authentication = token;

        assertSame(token, getToken());
        assertSame(token.getPrincipal(), getPrincial());
    }

    // -- requireAnyAudience --

    @Test
    public void testRequireAnyAudienceWithoutAuthenticationThrows() {
        assertThrows(AuthenticationCredentialsNotFoundException.class, () -> requireAnyAudience("http://entur.org"));
    }

    @Test
    public void testRequireAnyAudienceMatchSucceeds() {
        authentication = newToken(List.of("http://entur.org", "http://other.org"), "read");

        requireAnyAudience("http://entur.org");
        requireAnyAudience("http://none.org", "http://entur.org");
    }

    @Test
    public void testRequireAnyAudienceNoMatchThrows() {
        authentication = newToken(List.of("http://other.org"), "read");

        assertThrows(AccessDeniedException.class, () -> requireAnyAudience("http://entur.org"));
    }

    @Test
    public void testRequireAnyAudienceCollectionOverload() {
        authentication = newToken(List.of("http://entur.org"), "read");

        requireAnyAudience(Arrays.asList("http://entur.org"));
    }

    @Test
    public void testHasAnyAudienceMissingClaimThrows() {
        authentication = newToken(null, "read");

        assertThrows(IllegalArgumentException.class, () -> requireAnyAudience("http://entur.org"));
    }

    @Test
    public void testHasAnyAudienceWithStringClaim() {
        authentication = newToken("http://entur.org", "read");

        assertTrue(hasAnyAudience((JwtAuthenticationToken) authentication, java.util.Set.of("http://entur.org")));
    }

    @Test
    public void testHasAnyAudienceWithStringArrayClaim() {
        authentication = newToken(new String[] { "http://entur.org" }, "read");

        assertTrue(hasAnyAudience((JwtAuthenticationToken) authentication, java.util.Set.of("http://entur.org")));
    }

    @Test
    public void testHasAnyAudienceWithUnexpectedClaimTypeThrows() {
        authentication = newToken(42, "read");

        assertThrows(IllegalArgumentException.class,
                () -> hasAnyAudience((JwtAuthenticationToken) authentication, java.util.Set.of("http://entur.org")));
    }

    // -- requireAnyAuthority --

    @Test
    public void testRequireAnyAuthorityWithoutAuthenticationThrows() {
        assertThrows(AuthenticationCredentialsNotFoundException.class, () -> requireAnyAuthority("read"));
    }

    @Test
    public void testRequireAnyAuthoritySucceeds() {
        authentication = newToken(List.of("http://entur.org"), "read", "write");

        requireAnyAuthority("write", "delete");
    }

    @Test
    public void testRequireAnyAuthorityNoMatchThrows() {
        authentication = newToken(List.of("http://entur.org"), "read");

        assertThrows(AccessDeniedException.class, () -> requireAnyAuthority("delete"));
    }

    // -- requireAllAuthorities --

    @Test
    public void testRequireAllAuthoritiesWithoutAuthenticationThrows() {
        assertThrows(AuthenticationCredentialsNotFoundException.class, () -> requireAllAuthorities("read"));
    }

    @Test
    public void testRequireAllAuthoritiesSucceeds() {
        authentication = newToken(List.of("http://entur.org"), "read", "write");

        requireAllAuthorities("read");
        requireAllAuthorities("read", "write");
        requireAllAuthorities(java.util.Set.of("read", "write"));
        requireAllAuthorities(Arrays.asList("read"));
    }

    @Test
    public void testRequireAllAuthoritiesPartialMatchThrows() {
        authentication = newToken(List.of("http://entur.org"), "read");

        assertThrows(AccessDeniedException.class, () -> requireAllAuthorities("read", "write"));
    }

    @Test
    public void testHasAllAuthoritiesFalseWhenMissingOne() {
        JwtAuthenticationToken token = newToken(List.of("http://entur.org"), "read");

        assertFalse(hasAllAuthorities(token, java.util.Set.of("read", "write")));
    }
}
