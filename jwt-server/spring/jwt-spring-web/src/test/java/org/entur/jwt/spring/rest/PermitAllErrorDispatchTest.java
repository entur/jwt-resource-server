package org.entur.jwt.spring.rest;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
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
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import static com.google.common.truth.Truth.assertThat;

/**
 * Test that errors in permit-all endpoints keep their status for requests without a token,
 * i.e. that the error dispatch (to the error page) is not rejected as unauthenticated,
 * while protected endpoints (and the error page itself) still require a token.
 * <br>
 * Note: MockMvc does not perform error dispatches, so use a real server.
 */

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@TestPropertySource(properties = {"entur.authorization.permit-all.matcher.patterns=/actuator/health,/unprotected/**"})
// the authenticated requests load the JWKs, so do not share the context with tests which expect the JWKs not to be loaded yet
@DirtiesContext
public class PermitAllErrorDispatchTest {

    @LocalServerPort
    private int randomServerPort;

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    public void testUnsupportedMediaTypeOnWhitelist() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);
        HttpEntity<String> entity = new HttpEntity<String>("Hello", headers);

        ResponseEntity<String> response = restTemplate.exchange(url("/unprotected"), HttpMethod.POST, entity, String.class);

        assertErrorPage(response, HttpStatus.UNSUPPORTED_MEDIA_TYPE, "/unprotected");
    }

    @Test
    public void testMalformedJsonOnWhitelist() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<String>("{", headers);

        ResponseEntity<String> response = restTemplate.exchange(url("/unprotected"), HttpMethod.POST, entity, String.class);

        assertErrorPage(response, HttpStatus.BAD_REQUEST, "/unprotected");
    }

    @Test
    public void testNotFoundOnWhitelist() {
        HttpEntity<String> entity = new HttpEntity<String>(new HttpHeaders());

        ResponseEntity<String> response = restTemplate.exchange(url("/unprotected/nope"), HttpMethod.GET, entity, String.class);

        assertErrorPage(response, HttpStatus.NOT_FOUND, "/unprotected/nope");
    }

    @Test
    public void testMethodNotAllowedOnWhitelist() {
        HttpEntity<String> entity = new HttpEntity<String>(new HttpHeaders());

        ResponseEntity<String> response = restTemplate.exchange(url("/unprotected"), HttpMethod.DELETE, entity, String.class);

        assertErrorPage(response, HttpStatus.METHOD_NOT_ALLOWED, "/unprotected");
    }

    @Test
    public void testExceptionOnWhitelist() {
        HttpEntity<String> entity = new HttpEntity<String>(new HttpHeaders());

        ResponseEntity<String> response = restTemplate.exchange(url("/unprotected/exception"), HttpMethod.GET, entity, String.class);

        assertErrorPage(response, HttpStatus.INTERNAL_SERVER_ERROR, "/unprotected/exception");
    }

    @Test
    public void testProtectedResource() {
        HttpEntity<String> entity = new HttpEntity<String>(new HttpHeaders());

        ResponseEntity<String> response = restTemplate.exchange(url("/protected"), HttpMethod.GET, entity, String.class);

        assertUnauthorized(response);
    }

    @Test
    public void testNotFoundNotOnWhitelist() {
        HttpEntity<String> entity = new HttpEntity<String>(new HttpHeaders());

        ResponseEntity<String> response = restTemplate.exchange(url("/nope"), HttpMethod.GET, entity, String.class);

        assertUnauthorized(response);
    }

    @Test
    public void testMethodNotAllowedNotOnWhitelist() {
        HttpEntity<String> entity = new HttpEntity<String>(new HttpHeaders());

        ResponseEntity<String> response = restTemplate.exchange(url("/protected"), HttpMethod.DELETE, entity, String.class);

        assertUnauthorized(response);
    }

    @Test
    public void testErrorPageNotOnWhitelist() {
        HttpEntity<String> entity = new HttpEntity<String>(new HttpHeaders());

        ResponseEntity<String> response = restTemplate.exchange(url("/error"), HttpMethod.GET, entity, String.class);

        assertUnauthorized(response);
    }

    @Test
    public void testRejectedByFirewallNotOnWhitelist() {
        HttpEntity<String> entity = new HttpEntity<String>(new HttpHeaders());

        // rejected by the firewall before authorization, regardless of path
        ResponseEntity<String> response = restTemplate.exchange(url("/protected;x=y"), HttpMethod.GET, entity, String.class);

        assertErrorPage(response, HttpStatus.BAD_REQUEST, "/protected;x=y");
    }

    @Test
    public void testNotFoundNotOnWhitelistWithToken(@AccessToken(audience = "mock.my.audience") String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token);
        HttpEntity<String> entity = new HttpEntity<String>(headers);

        ResponseEntity<String> response = restTemplate.exchange(url("/nope"), HttpMethod.GET, entity, String.class);

        assertErrorPage(response, HttpStatus.NOT_FOUND, "/nope");
    }

    private String url(String path) {
        return "http://localhost:" + randomServerPort + path;
    }

    private static void assertErrorPage(ResponseEntity<String> response, HttpStatus status, String path) {
        assertThat(response.getStatusCode()).isEqualTo(status);
        assertThat(response.getHeaders().containsHeader(HttpHeaders.WWW_AUTHENTICATE)).isFalse();

        // rendered by the error page
        assertThat(response.getBody()).contains("\"status\":" + status.value());
        assertThat(response.getBody()).contains("\"path\":\"" + path + "\"");
    }

    private static void assertUnauthorized(ResponseEntity<String> response) {
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE)).startsWith("Bearer");
        assertThat(response.getBody()).isNull();
    }
}
