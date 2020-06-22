package org.entur.jwt.spring.demo;

import static io.restassured.RestAssured.given;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

@AuthorizationServer
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = { "entur.authorization.permit-all.ant-matcher.method.get.patterns=/actuator/**" })
public class ConcurrentAccessTest {

    // see also alternative approach with com.jayway.restassured:spring-mock-mvc

    @LocalServerPort
    private Integer port;

    @Test
    public void actuatorHealth() {
        given().port(port).log().all().when().get("/actuator/health").then().log().all().assertThat().statusCode(HttpStatus.OK.value());
    }

}
