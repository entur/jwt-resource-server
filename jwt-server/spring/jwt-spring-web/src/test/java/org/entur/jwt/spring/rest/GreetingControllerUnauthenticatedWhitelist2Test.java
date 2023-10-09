package org.entur.jwt.spring.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.restassured.http.ContentType;
import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

import static io.restassured.RestAssured.given;
/**
 * 
 * Test accessing methods without a token, with a whitelist for unprotected endpoints.
 * 
 * Test that opening a specific method does not open other methods.
 * 
 */

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {"entur.authorization.permit-all.matcher.method.get.patterns=/unprotected"})
public class GreetingControllerUnauthenticatedWhitelist2Test {

    @LocalServerPort
    protected int port;

    @Test
    public void getIsAllowed() throws Exception {
        given()
        .when()
            .log().all()
            .get("http://localhost:" + port + "/unprotected")
        .then()
            .log().all()
            .assertThat()
            .statusCode(HttpStatus.OK.value());
    }
    
    @Test
    public void postIsNotAllowed() throws Exception {
        given()
                .contentType(ContentType.JSON)
                .body(new ObjectMapper().writeValueAsString(new Greeting(1, "x")))
                .when()
                .log().all()
                .post("http://localhost:" + port + "/unprotected")
                .then()
                .log().all()
                .assertThat()
                .statusCode(HttpStatus.UNAUTHORIZED.value());
    }
}