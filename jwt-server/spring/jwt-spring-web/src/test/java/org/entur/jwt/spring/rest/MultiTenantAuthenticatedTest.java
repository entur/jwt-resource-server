package org.entur.jwt.spring.rest;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.claim.Issuer;
import org.entur.jwt.junit5.sabotage.Signature;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Multi-tenant integration tests for the JWT header-to-issuer cache and
 * fast-path issuer resolution introduced in {@code EnturOauth2ResourceServerCustomizer}.
 *
 * <p>Verifies that:
 * <ul>
 *   <li>Tokens from either configured issuer are accepted (slow path and fast path).</li>
 *   <li>Tokens with an invalid signature are rejected.</li>
 *   <li>Tokens whose issuer does not match any configured tenant are rejected.</li>
 * </ul>
 */
@AuthorizationServer("partner")
@AuthorizationServer("internal")
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@DirtiesContext
public class MultiTenantAuthenticatedTest {

    @LocalServerPort
    private int randomServerPort;

    @Autowired
    private TestRestTemplate restTemplate;

    // ------------------------------------------------------------------ slow path (first request per issuer)

    @Test
    public void testProtectedResourceWithPartnerToken(@AccessToken(by = "partner", audience = "mock.my.audience") String token) {
        ResponseEntity<Greeting> response = exchange(token, "/protected");
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody().getContent()).isEqualTo("Hello protected");
    }

    @Test
    public void testProtectedResourceWithInternalToken(@AccessToken(by = "internal", audience = "mock.my.audience") String token) {
        ResponseEntity<Greeting> response = exchange(token, "/protected");
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody().getContent()).isEqualTo("Hello protected");
    }

    // ------------------------------------------------------------------ fast path (second request, same issuer header)

    @Test
    public void testFastPathAfterCacheWarm(
            @AccessToken(by = "partner", audience = "mock.my.audience") String partnerToken,
            @AccessToken(by = "internal", audience = "mock.my.audience") String internalToken) {

        // Warm the cache for both issuers via the slow path
        assertThat(exchange(partnerToken, "/protected").getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(exchange(internalToken, "/protected").getStatusCode().is2xxSuccessful()).isTrue();

        // Subsequent requests from the same issuers should succeed via the fast path
        assertThat(exchange(partnerToken, "/protected").getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(exchange(internalToken, "/protected").getStatusCode().is2xxSuccessful()).isTrue();
    }

    // ------------------------------------------------------------------ negative cases

    @Test
    public void testPartnerTokenWithInvalidSignatureIsRejected(
            @AccessToken(by = "partner", audience = "mock.my.audience") @Signature("tampered") String token) {
        ResponseEntity<String> response = exchangeString(token, "/protected");
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    public void testTokenWithUnknownIssuerIsRejected(
            @AccessToken(by = "partner", audience = "mock.my.audience") @Issuer("https://unknown.issuer.example") String token) {
        ResponseEntity<String> response = exchangeString(token, "/protected");
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    // ------------------------------------------------------------------ helpers

    private ResponseEntity<Greeting> exchange(String token, String path) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token);
        String url = "http://localhost:" + randomServerPort + path;
        return restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), Greeting.class);
    }

    private ResponseEntity<String> exchangeString(String token, String path) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token);
        String url = "http://localhost:" + randomServerPort + path;
        return restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
    }
}
