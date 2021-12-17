package org.entur.jwt.spring.rest;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.*;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;

import static com.google.common.truth.Truth.assertThat;

/**
 *
 * Test accessing methods without a token, and without any whitelist.
 *
 * So all request must be authenticated.
 *
 */

@AuthorizationServer
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class GreetingControllerUnauthenticatedTest {

    @Autowired
    private WebTestClient webTestClient;

    @Test
    public void testUnprotectedResourceNotOnWhitelist() {
        webTestClient
            .get()
            .uri("/unprotected")
            .exchange()
            .expectStatus().isUnauthorized();
    }

    @Test
    public void testUnprotectedResourceWithOptionalTenantNotPresent() {
        webTestClient
            .get()
            .uri("/unprotected/optionalTenant")
            .exchange()
            .expectStatus().isUnauthorized();
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
    public void testActuatorNotOnWhitelist() {
        webTestClient
            .get()
            .uri("/actuator/someother")
            .exchange()
            .expectStatus().isUnauthorized();
    }
}
