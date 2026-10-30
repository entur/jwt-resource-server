package org.entur.jwt.spring;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeycloakJwtAuthorityEnricherTest {

    private ListAppender<ILoggingEvent> logAppender;

    @BeforeEach
    void setUpLogCapture() {
        logAppender = new ListAppender<>();
        logAppender.start();
        ((Logger) LoggerFactory.getLogger(KeycloakJwtAuthorityEnricher.class)).addAppender(logAppender);
    }

    @AfterEach
    void tearDown() {
        ((Logger) LoggerFactory.getLogger(KeycloakJwtAuthorityEnricher.class)).detachAppender(logAppender);
    }

    private List<String> warnings() {
        return logAppender.list.stream().filter(e -> e.getLevel() == Level.WARN).map(ILoggingEvent::getFormattedMessage).toList();
    }

    private Jwt jwtWithResourceAccess(Map<String, Object> resourceAccess) {
        Map<String, Object> headers = Collections.singletonMap("alg", "none");
        Map<String, Object> claims = resourceAccess == null
                ? Collections.singletonMap("sub", "subject")
                : Map.of("sub", "subject", "resource_access", resourceAccess);
        return new Jwt("token", Instant.now(), Instant.now().plusSeconds(60), headers, claims);
    }

    private List<String> enrich(KeycloakJwtAuthorityEnricher enricher, Jwt jwt) {
        Collection<GrantedAuthority> current = new ArrayList<>();
        enricher.enrich(current, jwt);
        return current.stream().map(GrantedAuthority::getAuthority).toList();
    }

    @Test
    void enrichesWithRolesFromResourceAccess() {
        KeycloakJwtAuthorityEnricher enricher = new KeycloakJwtAuthorityEnricher("my-test-client");

        Map<String, Object> resourceAccess = Map.of(
                "my-test-client", Map.of("roles", List.of("my-new-client-role")),
                "account", Map.of("roles", List.of("manage-account"))
        );

        // "account" entries are intentionally skipped
        assertEquals(List.of("ROLE_my-new-client-role"), enrich(enricher, jwtWithResourceAccess(resourceAccess)));
    }

    @Test
    void enrichesOnlyWithRolesOfConfiguredClient() {
        KeycloakJwtAuthorityEnricher enricher = new KeycloakJwtAuthorityEnricher("booking-api");

        Map<String, Object> resourceAccess = Map.of(
                "reporting-ui", Map.of("roles", List.of("admin")),
                "booking-api", Map.of("roles", List.of("booking-reader")),
                "account", Map.of("roles", List.of("manage-account"))
        );

        assertEquals(List.of("ROLE_booking-reader"), enrich(enricher, jwtWithResourceAccess(resourceAccess)));
    }

    @Test
    void doesNothingWhenConfiguredClientIsNotInResourceAccess() {
        KeycloakJwtAuthorityEnricher enricher = new KeycloakJwtAuthorityEnricher("booking-api");

        Map<String, Object> resourceAccess = Map.of(
                "reporting-ui", Map.of("roles", List.of("admin"))
        );

        assertTrue(enrich(enricher, jwtWithResourceAccess(resourceAccess)).isEmpty());
        assertTrue(warnings().isEmpty());
    }

    @Test
    void doesNotEnrichWithClientRolesWhenNoClientIdIsConfigured() {
        Map<String, Object> resourceAccess = Map.of(
                "reporting-ui", Map.of("roles", List.of("admin")),
                "booking-api", Map.of("roles", List.of("booking-reader"))
        );

        for (String clientId : new String[]{null, "", " "}) {
            KeycloakJwtAuthorityEnricher enricher = new KeycloakJwtAuthorityEnricher(clientId);
            assertNull(enricher.getClientId());

            assertTrue(enrich(enricher, jwtWithResourceAccess(resourceAccess)).isEmpty());
        }
    }

    @Test
    void warnsOnceWhenClientRolesAreIgnored() {
        KeycloakJwtAuthorityEnricher enricher = new KeycloakJwtAuthorityEnricher(null);

        Map<String, Object> resourceAccess = Map.of(
                "reporting-ui", Map.of("roles", List.of("admin"))
        );

        enrich(enricher, jwtWithResourceAccess(resourceAccess));
        enrich(enricher, jwtWithResourceAccess(resourceAccess));

        List<String> warnings = warnings();
        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).contains("entur.jwt.flavours.keycloak.client-id"));
    }

    @Test
    void doesNotWarnWhenNoClientRolesAreIgnored() {
        KeycloakJwtAuthorityEnricher enricher = new KeycloakJwtAuthorityEnricher(null);

        // i.e. tokens from other tenants (like Auth0) or without client roles
        enrich(enricher, jwtWithResourceAccess(null));
        enrich(enricher, jwtWithResourceAccess(Map.of("account", Map.of("roles", List.of("manage-account")))));
        enrich(enricher, jwtWithResourceAccess(Map.of("client-without-roles", Map.of("verify_caller", true))));

        assertTrue(warnings().isEmpty());
    }

    @Test
    void doesNotDuplicateExistingRolePrefix() {
        KeycloakJwtAuthorityEnricher enricher = new KeycloakJwtAuthorityEnricher("my-test-client");

        Map<String, Object> resourceAccess = Map.of(
                "my-test-client", Map.of("roles", List.of("ROLE_already-prefixed"))
        );

        assertEquals(List.of("ROLE_already-prefixed"), enrich(enricher, jwtWithResourceAccess(resourceAccess)));
    }

    @Test
    void doesNothingWhenNoResourceAccessClaim() {
        KeycloakJwtAuthorityEnricher enricher = new KeycloakJwtAuthorityEnricher("my-test-client");

        assertTrue(enrich(enricher, jwtWithResourceAccess(null)).isEmpty());
    }

    @Test
    void skipsResourceAccessEntryWithoutRoles() {
        KeycloakJwtAuthorityEnricher enricher = new KeycloakJwtAuthorityEnricher("client-without-roles");

        Map<String, Object> resourceAccess = Map.of(
                "client-without-roles", Map.of("verify_caller", true),
                "my-test-client", Map.of("roles", List.of("my-new-client-role"))
        );

        assertTrue(enrich(enricher, jwtWithResourceAccess(resourceAccess)).isEmpty());
    }

    @Test
    void skipsRolesWhichAreNotStrings() {
        KeycloakJwtAuthorityEnricher enricher = new KeycloakJwtAuthorityEnricher("my-test-client");

        Map<String, Object> resourceAccess = Map.of(
                "my-test-client", Map.of("roles", List.of(1L, "my-new-client-role"))
        );

        assertEquals(List.of("ROLE_my-new-client-role"), enrich(enricher, jwtWithResourceAccess(resourceAccess)));
    }

    @Test
    void doesNothingWhenResourceAccessClaimIsNotAnObject() {
        KeycloakJwtAuthorityEnricher enricher = new KeycloakJwtAuthorityEnricher("my-test-client");

        Map<String, Object> headers = Collections.singletonMap("alg", "none");
        Map<String, Object> claims = Map.of("sub", "subject", "resource_access", "my-test-client");
        Jwt jwt = new Jwt("token", Instant.now(), Instant.now().plusSeconds(60), headers, claims);

        assertTrue(enrich(enricher, jwt).isEmpty());
    }
}
