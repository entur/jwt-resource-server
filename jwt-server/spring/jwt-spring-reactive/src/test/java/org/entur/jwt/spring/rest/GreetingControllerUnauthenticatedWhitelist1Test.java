package org.entur.jwt.spring.rest;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Duration;

/**
 *
 * Test accessing methods without a token, but with a whitelist for the unprotected endpoints and actuator.
 *
 */

@AuthorizationServer
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = { "entur.authorization.permit-all.path-matcher.patterns=/actuator/health,/unprotected/**" })
public class GreetingControllerUnauthenticatedWhitelist1Test {

    @Autowired
    private WebTestClient webTestClient;

    @Test
    public void testUnprotectedResourceOnWhitelist() {
        webTestClient
            .get()
            .uri("/unprotected")
            .exchange()
            .expectStatus().is2xxSuccessful();
    }

    @Test
    public void testUnprotectedResourceWithOptionalTenantNotPresent() {
        webTestClient
            .get()
            .uri("/unprotected/optionalTenant")
            .exchange()
            .expectStatus().is2xxSuccessful();
    }

    @Test
    public void testUnprotectedResourceWithRequiredTenantNotPresent() {
        webTestClient
            .get()
            .uri("/unprotected/requiredTenant")
            .exchange()
            .expectStatus().isUnauthorized();
    }


    @Test
    public void testProtectedResource() {
        webTestClient
            .get()
            .uri("/protected")
            .exchange()
            .expectStatus().isUnauthorized();
    }


    @Test
    public void testProtectedResourceWithRequiredTenantNotPresent() {
        // note to self: this illustrates that the argument resolver runs BEFORE the
        // method permissions
        webTestClient
            .get()
            .uri("/protected/requiredTenant")
            .exchange()
            .expectStatus().isUnauthorized();
    }

    @Test
    public void testActuatorOnWhitelist() {
        webTestClient
            .get()
            .uri("/actuator/health")
            .exchange()
            .expectStatus().is2xxSuccessful();
    }
}
