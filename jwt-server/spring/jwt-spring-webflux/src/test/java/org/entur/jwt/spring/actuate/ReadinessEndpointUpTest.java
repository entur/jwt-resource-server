package org.entur.jwt.spring.actuate;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 * Test readiness probe up.
 *
 */

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class ReadinessEndpointUpTest extends AbstractActuatorTest {

    @LocalServerPort
    private int randomServerPort;

    @Test
    public void testReadiness() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        HttpEntity<String> entity = new HttpEntity<String>(headers);

        String url = "http://localhost:" + randomServerPort + "/actuator/health/readiness";

        HttpClient client = HttpClient.newHttpClient();
        // For custom configurations (e.g., proxy, timeout), use HttpClient.newBuilder()

        // 2. Create an HttpRequest
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url)) // Set the target URI
                .GET() // Specify the HTTP method (GET is default)
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        if(response.statusCode() != 200) {
            assertThat(response.statusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE.value());
            waitForHealth();

            response = client.send(request, HttpResponse.BodyHandlers.ofString());
            assertThat(response.statusCode()).isEqualTo(HttpStatus.OK.value());
        }

    }

}
