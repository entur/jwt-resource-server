package org.entur.jwt.spring.rest;

import static org.assertj.core.api.Assertions.assertThat;

import org.entur.jwt.junit5.AuthorizationServer;
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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
/**
 * 
 * Test that using a custom controller-advice is possible.
 * 
 */

@AuthorizationServer
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@ActiveProfiles("controllerAdvice")
public class InvalidAuthenticationTokenControllerAdviceTest {
    
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
        assertThat(response.getHeaders().get(CustomJwtFilterControllerAdvice.CONTROLLER_ADVICE)).containsExactly("true");
    }
    
    @Test 
    public void testProtectedResource() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer hvaomshelst");
        HttpEntity<String> entity = new HttpEntity<String>(headers);
        
        String url = "http://localhost:" + randomServerPort + "/protected";
        
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().get(CustomJwtFilterControllerAdvice.CONTROLLER_ADVICE)).containsExactly("true");
    }

}