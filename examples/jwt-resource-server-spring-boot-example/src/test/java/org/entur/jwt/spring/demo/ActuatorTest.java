package org.entur.jwt.spring.demo;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

import static io.restassured.RestAssured.given;

@AuthorizationServer
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = { "entur.authorization.permit-all.ant-matcher.method.get.patterns=/actuator/**" })
public class ActuatorTest {

    // see also alternative approach with com.jayway.restassured:spring-mock-mvc

    @LocalServerPort
    private Integer port;

    @Test
    public void actuatorHealth() {
        given().port(port).log().all().when().get("/actuator/health/readiness").then().log().all().assertThat().statusCode(HttpStatus.OK.value());
    }

}
