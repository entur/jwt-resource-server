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
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@AuthorizationServer
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = { "entur.cors.mode=api", "entur.cors.origins[0]=https://petstore.swagger.io", "entur.cors.origins[1]=https://developer.entur.org", "entur.cors.origins[2]=https://myportal.apigee.io", "entur.authorization.permit-all.ant-matcher.patterns=/unprotected", "entur.cors.methods[0]=GET", "entur.cors.methods[1]=POST", "entur.cors.methods[2]=OPTIONS"})
public class CorsAPIMethodsTest {

    @LocalServerPort
    protected int port;

    private List<String> allowedMethods = Arrays.asList("GET", "POST", "OPTIONS");
    private List<String> forbiddenMethods = Arrays.asList("PUT", "DELETE");

    private List<String> hosts = Arrays.asList("https://petstore.swagger.io", "https://myportal.apigee.io", "https://developer.entur.org");

    @Test
    public void cors_is_allowed() {
        hosts.forEach(host -> {
            allowedMethods.forEach(method -> {
                given().header("Origin", host).header("Access-Control-Request-Method", method).when().log().all().options("http://localhost:" + port + "/unprotected").then().log().all().assertThat().statusCode(HttpStatus.OK.value())
                        .header("Access-Control-Allow-Origin", host);
            });
        });
    }

    @Test
    public void cors_is_forbidden() {
        hosts.forEach(host -> {
            forbiddenMethods.forEach(method -> {
                given().header("Origin", host).header("Access-Control-Request-Method", method).when().log().all().options("http://localhost:" + port + "/unprotected").then().log().all().assertThat().statusCode(HttpStatus.FORBIDDEN.value());
            });
        });
    }
}
