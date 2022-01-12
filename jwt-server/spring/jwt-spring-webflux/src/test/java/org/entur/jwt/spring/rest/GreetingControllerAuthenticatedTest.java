package org.entur.jwt.spring.rest;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import java.util.List;
import java.util.Map.Entry;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.claim.Scope;
import org.entur.jwt.spring.rest.token.MyAccessToken;
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
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 *
 * Test accessing methods with a token, with the global setting of requiring
 * an Authorization header for all requests.
 *
 */

@AuthorizationServer
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class GreetingControllerAuthenticatedTest {

    @Autowired
    private WebTestClient webTestClient;

    @Test
    public void testUnprotectedResource(@AccessToken(audience = "mock.my.audience") String token) {
        Greeting greeting = webTestClient
            .get()
            .uri("/unprotected")
            .header(AUTHORIZATION, token)
            .exchange()
            .expectStatus().is2xxSuccessful()
            .returnResult(Greeting.class)
            .getResponseBody().blockLast();


        assertThat(greeting.getContent()).isEqualTo("Hello unprotected");
    }

    @Test
    public void testProtectedResource(@AccessToken(audience = "mock.my.audience") String token) {
        Greeting greeting = webTestClient
            .get()
            .uri("/protected")
            .header(AUTHORIZATION, token)
            .exchange()
            .expectStatus().is2xxSuccessful()
            .returnResult(Greeting.class)
            .getResponseBody().blockLast();

        assertThat(greeting.getContent()).isEqualTo("Hello protected");
    }

    @Test
    public void testProtectedResourceTenant(@MyAccessToken(myId = 1) String token) {
        webTestClient
            .get()
            .uri("/protected/requiredTenant")
            .header(AUTHORIZATION, token)
            .exchange()
            .expectStatus().is2xxSuccessful();
    }

    @Test
    public void testProtectedResourceTenantOfSpecificSubtype(@MyAccessToken(myId = 1) String token) {
        webTestClient.get()
            .uri("/protected/requiredPartnerTenant")
            .header(AUTHORIZATION, token)
            .exchange()
            .expectStatus().is2xxSuccessful();
    }

    @Test
    public void testSecurityHeaders(@AccessToken(audience = "mock.my.audience") String token) {
        HttpHeaders responseHeaders = webTestClient
            .get()
            .uri("/protected")
            .header(AUTHORIZATION, token)
            .exchange()
            .expectStatus().is2xxSuccessful()
            .returnResult(Greeting.class)
            .getResponseHeaders();

        assertThat(responseHeaders.get("X-Content-Type-Options")).contains("nosniff");
        assertThat(responseHeaders.get("X-XSS-Protection")).contains("1 ; mode=block");
        assertThat(responseHeaders.get("Cache-Control")).contains("no-cache, no-store, max-age=0, must-revalidate");
        assertThat(responseHeaders.get("Pragma")).contains("no-cache");
        assertThat(responseHeaders.get("Expires")).contains("0");
        assertThat(responseHeaders.get("X-Frame-Options")).contains("DENY");
    }

    @Test
    public void testStateless(@AccessToken(audience = "mock.my.audience") String token) {
        HttpHeaders responseHeaders = webTestClient
            .get()
            .uri("/protected")
            .header(AUTHORIZATION, token)
            .exchange()
            .expectStatus().is2xxSuccessful()
            .returnResult(Greeting.class)
            .getResponseHeaders();

        for (Entry<String, List<String>> entry : responseHeaders.entrySet()) {
            assertThat(entry.getKey().toLowerCase()).isNotEqualTo("set-cookie");
        }
    }

    @Test
    public void testProtectedResourceWithCorrectPermission(@MyAccessToken(myId = 1) @Scope("configure") String token) {
        Greeting greeting = webTestClient
            .get()
            .uri("/protected/permission")
            .header(AUTHORIZATION, token)
            .exchange()
            .expectStatus().is2xxSuccessful()
            .returnResult(Greeting.class)
            .getResponseBody().blockLast();

        assertThat(greeting.getContent()).isEqualTo("Hello protected partner tenant 1 with authority");
        assertThat(greeting.getAuthorities()).containsExactly("configure");
    }

    @Test
    public void testProtectedResourceWithWrongPermission(@MyAccessToken(myId = 1) @Scope("letmein") String token) {
        webTestClient
            .get()
            .uri("/protected/permission")
            .header(AUTHORIZATION, token)
            .exchange()
            .expectStatus().isForbidden();
    }

}
