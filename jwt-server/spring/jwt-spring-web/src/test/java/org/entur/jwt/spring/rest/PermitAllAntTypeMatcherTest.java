package org.entur.jwt.spring.rest;

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
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test permit-all patterns with matcher type {@code ant}, for any HTTP method as well as for a specific one.
 */

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@TestPropertySource(properties = {
        "entur.authorization.permit-all.matcher.type=ant",
        "entur.authorization.permit-all.matcher.patterns=/unprotected",
        "entur.authorization.permit-all.matcher.method.get.patterns=/unprotected/path/{pathVariable}"
})
public class PermitAllAntTypeMatcherTest {

    @LocalServerPort
    private int randomServerPort;

    @Autowired
    private TestRestTemplate restTemplate;

    private ResponseEntity<String> exchange(HttpMethod method, String path) {
        return restTemplate.exchange("http://localhost:" + randomServerPort + path, method, new HttpEntity<String>(new HttpHeaders()), String.class);
    }

    @Test
    public void testPatternForAnyMethod() {
        assertThat(exchange(HttpMethod.GET, "/unprotected").getStatusCode().is2xxSuccessful()).isTrue();
    }

    @Test
    public void testPatternForSpecificMethod() {
        assertThat(exchange(HttpMethod.GET, "/unprotected/path/123").getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(exchange(HttpMethod.DELETE, "/unprotected/path/123").getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    public void testProtectedResource() {
        assertThat(exchange(HttpMethod.GET, "/protected").getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
