package org.entur.jwt.spring.rest;

import static org.assertj.core.api.Assertions.assertThat;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
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
/**
 * 
 * Test accessing methods without an unknown token token.
 * 
 */

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class InvalidAuthenticationTokenTest {

    @LocalServerPort
    private int randomServerPort;
    
    @Autowired
    private TestRestTemplate restTemplate;

    @Test 
    public void testUnprotectedResource() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer hvaomshelst");
        HttpEntity<String> entity = new HttpEntity<String>(headers);

        String url = "http://localhost:" + randomServerPort + "/unprotected";
        
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
        
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
    
    @Test 
    public void testProtectedResource() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer hvaomshelst");
        HttpEntity<String> entity = new HttpEntity<String>(headers);
        
        String url = "http://localhost:" + randomServerPort + "/protected";
        
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

}