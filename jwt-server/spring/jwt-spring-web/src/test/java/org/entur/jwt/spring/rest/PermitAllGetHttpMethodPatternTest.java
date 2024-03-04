package org.entur.jwt.spring.rest;

import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.actuate.ListJwksHealthIndicator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.assertTrue;


@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {"entur.authorization.permit-all.matcher.method.get.patterns=/actuator/**,/unprotected/path/{pathVariable}"})
public class PermitAllGetHttpMethodPatternTest {

    @LocalServerPort
    private int randomServerPort;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private ListJwksHealthIndicator healthIndicator;

    @Test
    public void testUnprotectedResourceWithPathVariableOnWhitelist() {
        HttpHeaders headers = new HttpHeaders();
        HttpEntity<String> entity = new HttpEntity<String>(headers);

        String url = "http://localhost:" + randomServerPort + "/unprotected/path/123";

        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);

        assertTrue(response.getStatusCode().is2xxSuccessful());
    }

    @Test
    public void testActuatorOnWhitelist() throws Exception {
        // make sure health is ready before visiting
        healthIndicator.getHealth(false);

        long deadline = System.currentTimeMillis() + 1000;
        while(System.currentTimeMillis() < deadline && !healthIndicator.isIdle()) {
            Thread.sleep(10);
        }

        HttpHeaders headers = new HttpHeaders();
        HttpEntity<String> entity = new HttpEntity<String>(headers);

        String url = "http://localhost:" + randomServerPort + "/actuator/health";

        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);

        assertTrue(response.getStatusCode().is2xxSuccessful());
    }   
}