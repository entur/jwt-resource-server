package org.entur.jwt.spring.rest;

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
import org.springframework.test.context.TestPropertySource;

import static com.google.common.truth.Truth.assertThat;

/**
 * Test that errors in permit-all endpoints keep their status when authorization is enabled but JWT is disabled.
 * <br>
 * Note: MockMvc does not perform error dispatches, so use a real server.
 */

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@TestPropertySource(properties = {
        "entur.jwt.enabled=false",
        "management.endpoint.health.group.readiness.include=readinessState",
        "entur.authorization.permit-all.matcher.patterns=/actuator/health,/unprotected/**"
})
public class PermitAllErrorDispatchWithoutJwtTest {

    @LocalServerPort
    private int randomServerPort;

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    public void testUnprotectedResourceOnWhitelist() {
        HttpEntity<String> entity = new HttpEntity<String>(new HttpHeaders());

        ResponseEntity<String> response = restTemplate.exchange(url("/unprotected"), HttpMethod.GET, entity, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void testUnsupportedMediaTypeOnWhitelist() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);
        HttpEntity<String> entity = new HttpEntity<String>("Hello", headers);

        ResponseEntity<String> response = restTemplate.exchange(url("/unprotected"), HttpMethod.POST, entity, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNSUPPORTED_MEDIA_TYPE);
    }

    @Test
    public void testNotFoundOnWhitelist() {
        HttpEntity<String> entity = new HttpEntity<String>(new HttpHeaders());

        ResponseEntity<String> response = restTemplate.exchange(url("/unprotected/nope"), HttpMethod.GET, entity, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    public void testProtectedResource() {
        HttpEntity<String> entity = new HttpEntity<String>(new HttpHeaders());

        ResponseEntity<String> response = restTemplate.exchange(url("/protected"), HttpMethod.GET, entity, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    public void testNotFoundNotOnWhitelist() {
        HttpEntity<String> entity = new HttpEntity<String>(new HttpHeaders());

        ResponseEntity<String> response = restTemplate.exchange(url("/nope"), HttpMethod.GET, entity, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    private String url(String path) {
        return "http://localhost:" + randomServerPort + path;
    }
}
