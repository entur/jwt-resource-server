package org.entur.jwt.spring.actuate;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

import java.io.File;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

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

    @Value("${entur.jwt.tenants.unreliable.jwk.location}")
    private String jwkLocation;

    @Test 
    public void testReadinessDownWithTransistionToUp() throws Exception {
        String url = "http://localhost:" + randomServerPort + "/actuator/health/readiness";
        
        File jwkFile = new File(jwkLocation.substring(7));
        File jwkRenameFile = new File(jwkFile.getParentFile(), jwkFile.getName() + ".renamed");
        
        assertTrue(jwkFile.renameTo(jwkRenameFile));

        HttpClient client = HttpClient.newHttpClient();
        // For custom configurations (e.g., proxy, timeout), use HttpClient.newBuilder()

        // 2. Create an HttpRequest
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url)) // Set the target URI
                .GET() // Specify the HTTP method (GET is default)
                .build();

        HttpResponse<String> down = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(down.statusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE.value());
        waitForHealth();

        assertTrue(jwkRenameFile.renameTo(jwkFile));

        down = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(down.statusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE.value());

        waitForHealth();

        HttpResponse<String> up = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(up.statusCode()).isEqualTo(HttpStatus.OK.value());
    }

}