package org.entur.jwt.spring.rest;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
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
@TestPropertySource(properties = { "entur.authorization.permit-all.ant-matcher.patterns=/actuator/health,/unprotected/**" })
public class GreetingControllerUnauthenticatedWhitelist1Test {

    @Autowired
    private WebTestClient webTestClient;

    @BeforeEach
    public void setUp() {
        webTestClient = webTestClient
            .mutate()
            .responseTimeout(Duration.ofMillis(1000000))
            .build();
    }

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
            .expectStatus().isForbidden();
    }


    @Test
    public void testProtectedResource() {
        webTestClient
            .get()
            .uri("/protected")
            .exchange()
            .expectStatus().isForbidden();
    }


    @Test
    public void testProtectedResourceWithRequiredTenantNotPresent() {
        // note to self: this illustrates that the argument resolver runs BEFORE the
        // method permissions
        webTestClient
            .get()
            .uri("/protected/requiredTenant")
            .exchange()
            .expectStatus().isForbidden();
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
