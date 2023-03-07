package org.entur.jwt.spring.demo;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.claim.StringArrayClaim;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

import static io.restassured.RestAssured.given;

/**
 * 
 * Test accessing methods with a valid bearer token.
 *
 */

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@TestPropertySource(properties = { "entur.authorization.permit-all.ant-matcher.method.get.patterns=/actuator/**,/unprotected" })
public class GreetingControllerTest {

    @LocalServerPort
    private int port;

    @Test
    public void testUnprotectedEndpoint() {
        given().port(port).log().all().when().get("/unprotected").then().log().all().assertThat().statusCode(HttpStatus.OK.value());
    }

    @Test
    public void testProtectedEndpoint(@AccessToken(audience = "https://my.audience") String token) {
        given().port(port).log().all().when().header("Authorization", token).get("/protected").then().log().all().assertThat().statusCode(HttpStatus.OK.value());
    }

    @Test
    public void testProtectedEndpointWithArgument(@AccessToken(audience = "https://my.audience") String token) {
        given().port(port).log().all().when().header("Authorization", token).get("/protected/withArgument").then().log().all().assertThat().statusCode(HttpStatus.OK.value());
    }

    @Test
    public void testProtectedEndpointWithPermission(@AccessToken(audience = "https://my.audience") @StringArrayClaim(name = "permissions", value = { "configure" }) String token) {
        given().port(port).log().all().when().header("Authorization", token).get("/protected/withPermission").then().log().all().assertThat().statusCode(HttpStatus.OK.value());
    }

    @Test
    public void testProtectedEndpointWithoutToken() {
        given().port(port).log().all().when().get("/protected").then().log().all().assertThat().statusCode(HttpStatus.FORBIDDEN.value());
    }

    @Test
    public void testProtectedEndpointWithIncorrectPermission(@AccessToken(audience = "https://my.audience") @StringArrayClaim(name = "permissions", value = { "myPermission" }) String token) {
        given().port(port).log().all().when().header("Authorization", token).get("/protected/withPermission").then().log().all().assertThat().statusCode(HttpStatus.FORBIDDEN.value());
    }
}