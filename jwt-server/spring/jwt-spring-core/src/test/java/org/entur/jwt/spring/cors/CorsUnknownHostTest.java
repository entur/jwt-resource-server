package org.entur.jwt.spring.cors;

import static io.restassured.RestAssured.given;

import java.util.Arrays;
import java.util.List;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit.jupiter.SpringExtension;

/**
 * Note: This behavior can be supported by a filter in the API gateway which
 * simply checks if the Origin header is present and if so whether the domain is
 * known.
 *
 */
@AuthorizationServer
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class CorsUnknownHostTest {

    @LocalServerPort
    protected int port;

    private List<String> methods = Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH");

    @Test
    public void cors_options_is_not_allowed() {
        methods.forEach(method -> {
            given().header("Origin", "https://ukjent.swagger.io").header("Access-Control-Request-Method", method).when().log().all().options("http://localhost:" + port + "/unprotected").then().log().all().assertThat()
                    .statusCode(HttpStatus.FORBIDDEN.value());
        });
    }

    @Test
    public void cors_request_is_not_allowed() {
        methods.forEach(method -> {
            given().header("Origin", "https://ukjent.swagger.io").when().log().all().get("http://localhost:" + port + "/unprotected").then().log().all().assertThat().statusCode(HttpStatus.FORBIDDEN.value());
        });
    }
}
