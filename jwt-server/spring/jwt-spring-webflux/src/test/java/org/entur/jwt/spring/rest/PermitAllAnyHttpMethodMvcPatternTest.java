package org.entur.jwt.spring.rest;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.Ignore;
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
@TestPropertySource(properties = {"entur.authorization.permit-all.matcher.patterns=/actuator/**,/unprotected/path/{pathVariable}"})

@Deprecated // seems ant + mvc has been merged to "path matchers", investigate further
public class PermitAllAnyHttpMethodMvcPatternTest {

    @Autowired
    private WebTestClient webTestClient;

    @Test
    @Ignore
    public void testUnprotectedResourceWithPathVariableOnWhitelist() {
        webTestClient
                .get()
                .uri("/unprotected/path/123")
                .exchange()
                .expectStatus().is2xxSuccessful();
    }

    @Test
    @Ignore
    public void testActuatorOnWhitelist() {
        webTestClient
                .get()
                .uri("/actuator/health")
                .exchange()
                .expectStatus().is2xxSuccessful();
    }
}