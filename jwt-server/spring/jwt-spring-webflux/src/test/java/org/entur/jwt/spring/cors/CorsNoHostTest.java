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
@TestPropertySource(properties = { "entur.cors.mode=api", "entur.authorization.permit-all.ant-matcher.patterns=/unprotected"})
public class CorsNoHostTest {

    @LocalServerPort
    protected int port;

    private List<String> hosts = Arrays.asList("http://min.andre.host");

    @Test
    public void request_is_allowed_for_no_origin() {
        hosts.forEach(host -> {
            given().when().log().all().get("http://localhost:" + port + "/unprotected").then().log().all().assertThat().statusCode(HttpStatus.OK.value());
        });
    }
}
