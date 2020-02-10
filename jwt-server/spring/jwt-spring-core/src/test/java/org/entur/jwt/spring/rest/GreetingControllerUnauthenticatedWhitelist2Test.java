package org.entur.jwt.spring.rest;

import static io.restassured.RestAssured.given;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.restassured.http.ContentType;
/**
 * 
 * Test accessing methods without a token, with a whitelist for unprotected endpoints.
 * 
 * Test that opening a specific method does not open other methods.
 * 
 */

@AuthorizationServer
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = { "entur.authorization.permit-all.mvc-matcher.method.get.patterns=/unprotected" })
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
            .statusCode(HttpStatus.FORBIDDEN.value());
    }
}