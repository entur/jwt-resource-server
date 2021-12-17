package org.entur.jwt.spring.rest;

import static org.assertj.core.api.Assertions.assertThat;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Duration;

/**
 *
 * Test that using a custom controller-advice is possible.
 *
 */

@AuthorizationServer
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@ActiveProfiles("customEntryPoint")
public class InvalidAuthenticationTokenControllerAdviceTest {

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
    public void testUnprotectedResource() {
        HttpHeaders responseHeaders = webTestClient
            .get()
            .uri("/unprotected")
            .header("Authorization", "Bearer hvaomshelst")
            .exchange()
            .expectStatus().isUnauthorized()
            .returnResult(String.class)
            .getResponseHeaders();

        assertThat(responseHeaders.get(CustomServerAuthenticationEntryPoint.ENTRY_POINT)).containsExactly("true");
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

        assertThat(responseHeaders.get(CustomServerAuthenticationEntryPoint.ENTRY_POINT)).containsExactly("true");
    }

}
