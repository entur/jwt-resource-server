package org.entur.jwt.spring.rest;

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
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.List;
import java.util.Map.Entry;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test accessing methods with a token, with the global setting of requiring
 * an Authorization header for all requests.
 */

@AuthorizationServer
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class GreetingControllerAuthenticatedTest {

    @LocalServerPort
    private int randomServerPort;

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    public void testUnprotectedResource(@AccessToken(audience = "mock.my.audience") String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token);
        HttpEntity<String> entity = new HttpEntity<String>(headers);

        String url = "http://localhost:" + randomServerPort + "/unprotected";

        ResponseEntity<Greeting> response = restTemplate.exchange(url, HttpMethod.GET, entity, Greeting.class);
        assertTrue(response.getStatusCode().is2xxSuccessful());

        assertThat(response.getBody().getContent()).isEqualTo("Hello unprotected");
    }

    @Test
    public void testProtectedResource(@AccessToken(audience = "mock.my.audience") String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token);
        HttpEntity<String> entity = new HttpEntity<String>(headers);

        String url = "http://localhost:" + randomServerPort + "/protected";

        ResponseEntity<Greeting> response = restTemplate.exchange(url, HttpMethod.GET, entity, Greeting.class);
        assertTrue(response.getStatusCode().is2xxSuccessful());

        assertThat(response.getBody().getContent()).isEqualTo("Hello protected");
    }

    @Test
    public void testSecurityHeaders(@AccessToken(audience = "mock.my.audience") String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token);
        HttpEntity<String> entity = new HttpEntity<String>(headers);

        String url = "http://localhost:" + randomServerPort + "/protected";

        ResponseEntity<Greeting> response = restTemplate.exchange(url, HttpMethod.GET, entity, Greeting.class);
        assertTrue(response.getStatusCode().is2xxSuccessful());

        HttpHeaders responseHeaders = response.getHeaders();
        assertThat(responseHeaders.get("X-Content-Type-Options")).contains("nosniff");
        assertThat(responseHeaders.get("Cache-Control")).contains("no-cache, no-store, max-age=0, must-revalidate");
        assertThat(responseHeaders.get("Pragma")).contains("no-cache");
        assertThat(responseHeaders.get("Expires")).contains("0");
        assertThat(responseHeaders.get("X-Frame-Options")).contains("DENY");
        assertThat(responseHeaders.get("X-XSS-Protection")).contains("0");
    }

    @Test
    public void testStateless(@AccessToken(audience = "mock.my.audience") String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token);
        HttpEntity<String> entity = new HttpEntity<String>(headers);

        String url = "http://localhost:" + randomServerPort + "/protected";

        ResponseEntity<Greeting> response = restTemplate.exchange(url, HttpMethod.GET, entity, Greeting.class);
        assertTrue(response.getStatusCode().is2xxSuccessful());

        HttpHeaders responseHeaders = response.getHeaders();
        for (Entry<String, List<String>> entry : responseHeaders.entrySet()) {
            assertThat(entry.getKey().toLowerCase()).isNotEqualTo("set-cookie");
        }
    }

    @Test
    public void testProtectedResourceWithCorrectPermission(@AccessToken(audience = "mock.my.audience") @Scope("configure") String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token);
        HttpEntity<String> entity = new HttpEntity<String>(headers);

        String url = "http://localhost:" + randomServerPort + "/protected/permission";
        
        ResponseEntity<Greeting> response = restTemplate.exchange(url, HttpMethod.GET, entity, Greeting.class);
        assertTrue(response.getStatusCode().is2xxSuccessful(), response.getStatusCode().toString());

        assertThat(response.getBody().getContent()).isEqualTo("Hello protected with authority");
        assertThat(response.getBody().getAuthorities()).containsExactly("configure");
    }

    @Test
    public void testProtectedResourceWithWrongPermission(@AccessToken(audience = "mock.my.audience") @Scope("letmein") String token) {

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token);
        HttpEntity<String> entity = new HttpEntity<String>(headers);

        String url = "http://localhost:" + randomServerPort + "/protected/permission";

        ResponseEntity<Greeting> response = restTemplate.exchange(url, HttpMethod.GET, entity, Greeting.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }
    
}