package org.entur.jwt.spring.rest;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.headers.KeyIdHeader;
import org.entur.jwt.junit5.sabotage.Signature;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.*;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Duration;

/**
 *
 * Test accessing methods without an unknown token token.
 *
 */

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class InvalidAuthenticationTokenTest {

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
        webTestClient
            .get()
            .uri("/unprotected")
            .header("Authorization", "Bearer hvaomshelst")
            .exchange()
            .expectStatus().isForbidden();
    }

    @Test
    public void testProtectedResource() {
        webTestClient
            .get()
            .uri("/protected")
            .header("Authorization", "Bearer hvaomshelst")
            .exchange()
            .expectStatus().isForbidden();
    }

    @Test
    public void testProtectedResourceWithInvalidSignature(@AccessToken(audience = "https://my.audience") @Signature("cheat") String header) {
        webTestClient
            .get()
            .uri("/protected")
            .header("Authorization", "Bearer hvaomshelst")
            .exchange()
            .expectStatus().isForbidden();

    }

    @Test
    public void testProtectedResourceWithInvalidKeyId(@AccessToken(audience = "https://my.audience") @KeyIdHeader("abc") String header) {
        HttpHeaders responseHeaders = webTestClient
            .get()
            .uri("/protected")
            .header("Authorization", "Bearer hvaomshelst")
            .exchange()
            .expectStatus().isForbidden()
            .returnResult(String.class)
            .getResponseHeaders();

        System.out.println(responseHeaders.get("Location"));
    }


}
