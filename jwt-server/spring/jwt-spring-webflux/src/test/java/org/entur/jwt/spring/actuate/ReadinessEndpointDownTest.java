package org.entur.jwt.spring.actuate;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;

import java.io.File;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertTrue;
/**
 * 
 * Test readiness probe repair. 
 * 
 * Rename the jwk file so that it first cannot be found, check that state is down.
 * Then later restore the file and verify that state is up. 
 * 
 */

@AuthorizationServer("unreliable")
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)

// speed up test
@TestPropertySource(properties = {
        "entur.jwt.jwk.rateLimit.enabled=false",
})

public class ReadinessEndpointDownTest extends AbstractActuatorTest {

    @LocalServerPort
    private int randomServerPort;
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Value("${entur.jwt.tenants.unreliable.jwk.location}")
    private String jwkLocation;


    @Test 
    public void testReadinessDownWithTransistionToUp() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        HttpEntity<String> entity = new HttpEntity<String>(headers);

        String url = "http://localhost:" + randomServerPort + "/actuator/health/readiness";
        
        File jwkFile = new File(jwkLocation.substring(7));
        File jwkRenameFile = new File(jwkFile.getParentFile(), jwkFile.getName() + ".renamed");
        
        assertTrue(jwkFile.renameTo(jwkRenameFile));

        waitForHealth();

        ResponseEntity<String> down = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
        assertThat(down.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        
        assertTrue(jwkRenameFile.renameTo(jwkFile));

        waitForHealth();

        ResponseEntity<String> up = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
        assertThat(up.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

}