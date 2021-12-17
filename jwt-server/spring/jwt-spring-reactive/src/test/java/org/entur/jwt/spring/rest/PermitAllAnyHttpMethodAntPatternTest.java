package org.entur.jwt.spring.rest;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;

@AuthorizationServer
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = { "entur.authorization.permit-all.path-matcher.patterns=/actuator/**,/unprotected/path/{pathVariable}" })
public class PermitAllAnyHttpMethodAntPatternTest {

    @Autowired
    private WebTestClient webTestClient;

    @Test
    public void testUnprotectedResourceWithPathVariableOnWhitelist() {
        webTestClient
            .get()
            .uri("/unprotected/path/123")
            .exchange()
            .expectStatus().is2xxSuccessful();
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
