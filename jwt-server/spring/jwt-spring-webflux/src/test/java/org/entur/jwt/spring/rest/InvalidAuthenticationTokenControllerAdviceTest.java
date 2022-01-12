package org.entur.jwt.spring.rest;

import static org.assertj.core.api.Assertions.assertThat;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 *
 * Test that using a custom controller-advice is possible.
 *
 */

@AuthorizationServer
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@ActiveProfiles("customEntryPoint")
@Disabled("This functionality is not supported yet")
public class InvalidAuthenticationTokenControllerAdviceTest {

    @Autowired
    private WebTestClient webTestClient;

    @Test
    public void testUnprotectedResource() {
        HttpHeaders responseHeaders = webTestClient
            .get()
            .uri("/unprotected")
            .header("Authorization", "Bearer hvaomshelst")
            .exchange()
            .expectStatus().isUnauthorized()
            .returnResult(String.class)
            .getResponseHeaders();

        assertThat(responseHeaders.get(CustomJwtFilterControllerAdvice.CONTROLLER_ADVICE)).containsExactly("true");
    }

    @Test
    public void testProtectedResource() {
        HttpHeaders responseHeaders = webTestClient
            .get()
            .uri("/protected")
            .header("Authorization", "Bearer hvaomshelst")
            .exchange()
            .expectStatus().isUnauthorized()
            .returnResult(String.class)
            .getResponseHeaders();

        assertThat(responseHeaders.get(CustomJwtFilterControllerAdvice.CONTROLLER_ADVICE)).containsExactly("true");
    }

}
