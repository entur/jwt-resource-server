package org.entur.jwt.spring.rest;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.headers.AlgorithmHeader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test accessing a protected method with tokens signed using different algorithms.
 */

@AuthorizationServer
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
public class AlgorithmHeaderTest {

    @LocalServerPort
    private int randomServerPort;

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    public void testRS512(@AccessToken(audience = "mock.my.audience") @AlgorithmHeader("RS512") String token) {
        assertProtectedResource(token);
    }

    @Test
    public void testPS256(@AccessToken(audience = "mock.my.audience") @AlgorithmHeader("PS256") String token) {
        assertProtectedResource(token);
    }

    @Test
    public void testES256(@AccessToken(audience = "mock.my.audience") @AlgorithmHeader("ES256") String token) {
        assertProtectedResource(token);
    }

    @Test
    public void testES384(@AccessToken(audience = "mock.my.audience") @AlgorithmHeader("ES384") String token) {
        assertProtectedResource(token);
    }

    @Test
    public void testES512(@AccessToken(audience = "mock.my.audience") @AlgorithmHeader("ES512") String token) {
        assertProtectedResource(token);
    }

    private void assertProtectedResource(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token);
        HttpEntity<String> entity = new HttpEntity<String>(headers);

        String url = "http://localhost:" + randomServerPort + "/protected";

        ResponseEntity<Greeting> response = restTemplate.exchange(url, HttpMethod.GET, entity, Greeting.class);
        assertTrue(response.getStatusCode().is2xxSuccessful());

        assertThat(response.getBody().getContent()).isEqualTo("Hello protected");
    }
}
