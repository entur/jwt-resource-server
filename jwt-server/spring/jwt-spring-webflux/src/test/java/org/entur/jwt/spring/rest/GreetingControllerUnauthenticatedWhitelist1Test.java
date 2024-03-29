package org.entur.jwt.spring.rest;

import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.actuate.AbstractActuatorTest;
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
@TestPropertySource(properties = {"entur.authorization.permit-all.matcher.patterns=/actuator/health,/unprotected/**"})
public class GreetingControllerUnauthenticatedWhitelist1Test extends AbstractActuatorTest {

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
    public void testProtectedResource() {
        webTestClient
                .get()
                .uri("/protected")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    public void testActuatorOnWhitelist() throws Exception {
        webTestClient
                .get()
                .uri("/actuator/health")
                .exchange()
                .expectStatus().is5xxServerError();

        waitForHealth();
        webTestClient
            .get()
            .uri("/actuator/health")
            .exchange()
            .expectStatus().is2xxSuccessful();
    }
}
