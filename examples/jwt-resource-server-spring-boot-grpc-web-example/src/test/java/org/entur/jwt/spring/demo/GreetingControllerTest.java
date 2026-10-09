package org.entur.jwt.spring.demo;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;

import static io.restassured.RestAssured.given;

/**
 * REST endpoints, with and without a valid bearer token.
 */
@AuthorizationServer
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class GreetingControllerTest {

    @LocalServerPort
    private int port;

    @Test
    public void testUnprotectedEndpoint() {
        given().port(port).when().get("/unprotected").then().assertThat().statusCode(HttpStatus.OK.value());
    }

    @Test
    public void testProtectedEndpoint(@AccessToken(audience = "https://my.audience") String token) {
        given().port(port).when().header("Authorization", token).get("/protected").then().assertThat().statusCode(HttpStatus.OK.value());
    }

    @Test
    public void testProtectedEndpointWithoutToken() {
        given().port(port).when().get("/protected").then().assertThat().statusCode(HttpStatus.UNAUTHORIZED.value());
    }
}
