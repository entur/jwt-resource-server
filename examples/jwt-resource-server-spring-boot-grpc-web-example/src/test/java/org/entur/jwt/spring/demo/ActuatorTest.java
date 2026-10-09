package org.entur.jwt.spring.demo;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.annotation.DirtiesContext;

import static io.restassured.RestAssured.given;

/**
 * Health probes do not require a token, also with the gRPC module present.
 */
@AuthorizationServer
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext
public class ActuatorTest {

    @LocalServerPort
    private int port;

    @Test
    public void testLiveness() {
        given().port(port).when().get("/actuator/health/liveness").then().assertThat().statusCode(HttpStatus.OK.value());
    }

    @Test
    public void testReadiness() {
        given().port(port).when().get("/actuator/health/readiness").then().assertThat().statusCode(HttpStatus.OK.value());
    }
}
