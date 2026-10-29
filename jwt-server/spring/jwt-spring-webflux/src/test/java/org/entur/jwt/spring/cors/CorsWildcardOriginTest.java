package org.entur.jwt.spring.cors;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.Arrays;
import java.util.List;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.nullValue;

/**
 * Any origin is allowed without credentials; access-tokens in the Authorization header do not need credentials.
 */
@AuthorizationServer
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {"entur.cors.mode=api", "entur.cors.origins[0]=*", "entur.authorization.permit-all.matcher.patterns=/unprotected"})
public class CorsWildcardOriginTest {

    @LocalServerPort
    protected int port;

    private List<String> methods = Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS");

    private List<String> hosts = Arrays.asList("https://petstore.swagger.io", "https://myportal.apigee.io", "https://developer.entur.org");

    @Test
    public void cors_options_is_allowed() {
        hosts.forEach(host -> {
            methods.forEach(method -> {
                given().header("Origin", host).header("Access-Control-Request-Method", method).header("Access-Control-Request-Headers", "Authorization").when().log().all().options("http://localhost:" + port + "/unprotected").then().log().all().assertThat().statusCode(HttpStatus.OK.value())
                        .header("Access-Control-Allow-Origin", "*")
                        .header("Access-Control-Allow-Headers", "Authorization")
                        .header("Access-Control-Allow-Credentials", nullValue());
            });
        });
    }

    @Test
    public void cors_options_is_allowed_for_protected_resource() {
        // preflight requests carry no credentials, so must be handled before authentication
        hosts.forEach(host -> {
            methods.forEach(method -> {
                given().header("Origin", host).header("Access-Control-Request-Method", method).header("Access-Control-Request-Headers", "Authorization").when().log().all().options("http://localhost:" + port + "/protected").then().log().all().assertThat().statusCode(HttpStatus.OK.value())
                        .header("Access-Control-Allow-Origin", "*")
                        .header("Access-Control-Allow-Headers", "Authorization")
                        .header("Access-Control-Allow-Credentials", nullValue());
            });
        });
    }

    @Test
    public void cors_request_is_allowed() {
        hosts.forEach(host -> {
            given().header("Origin", host).when().log().all().get("http://localhost:" + port + "/unprotected").then().log().all().assertThat().statusCode(HttpStatus.OK.value())
                    .header("Access-Control-Allow-Origin", "*")
                    .header("Access-Control-Allow-Credentials", nullValue());
        });
    }
}
