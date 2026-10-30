package org.entur.jwt.spring.grpc.netty;

import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.grpc.AbstractGrpcTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.annotation.DirtiesContext;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The gRPC module also runs a servlet container (i.e. for actuator). Verify that the gRPC JWT decoder(s)
 * do not activate Spring Boot's default resource server security filter chain, which would require a JWT for
 * all HTTP endpoints, including the health probes.
 */
@AuthorizationServer("a")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext
public class HttpActuatorHealthContextTest extends AbstractGrpcTest {

    @Autowired
    private ApplicationContext context;

    @Test
    public void testNoJwtDecoderBean() {
        assertThat(context.getBeanNamesForType(JwtDecoder.class)).isEmpty();
        assertThat(context.containsBean("jwtSecurityFilterChain")).isFalse();
    }

    @Test
    public void testHealthProbesDoNotRequireAuthentication() throws Exception {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + randomServerPort + "/actuator/health/liveness")).GET().build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            assertThat(response.statusCode()).isEqualTo(200);
        }
    }
}
