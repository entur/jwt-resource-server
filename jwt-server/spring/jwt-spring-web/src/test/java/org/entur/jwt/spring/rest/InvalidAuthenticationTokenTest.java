package org.entur.jwt.spring.rest;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.headers.KeyIdHeader;
import org.entur.jwt.junit5.sabotage.Signature;
import org.junit.jupiter.api.Test;
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

import static org.assertj.core.api.Assertions.assertThat;
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

    @Test 
    public void testProtectedResourceWithInvalidSignature(@AccessToken(audience = "https://my.audience") @Signature("cheat") String header) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer hvaomshelst");
        HttpEntity<String> entity = new HttpEntity<String>(headers);
        
        String url = "http://localhost:" + randomServerPort + "/protected";
        
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
    
    @Test 
    public void testProtectedResourceWithInvalidKeyId(@AccessToken(audience = "https://my.audience") @KeyIdHeader("abc") String header) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer hvaomshelst");
        HttpEntity<String> entity = new HttpEntity<String>(headers);
        
        String url = "http://localhost:" + randomServerPort + "/protected";
        
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
        System.out.println(response.getHeaders().get("Location"));
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
    
    
}