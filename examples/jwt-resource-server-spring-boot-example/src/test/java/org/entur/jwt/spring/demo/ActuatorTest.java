package org.entur.jwt.spring.demo;

import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.actuate.ListJwksHealthIndicator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;

import static io.restassured.RestAssured.given;

@AuthorizationServer
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {"entur.authorization.permit-all.matcher.method.get.patterns=/actuator/**"})
public class ActuatorTest {

    // see also alternative approach with com.jayway.restassured:spring-mock-mvc

    @Autowired
    private ListJwksHealthIndicator healthIndicator;

    @LocalServerPort
    private Integer port;

    public void waitForHealth() throws Exception {
        // make sure health is ready before visiting
        long deadline = System.currentTimeMillis() + 1000;
        while (System.currentTimeMillis() < deadline && !healthIndicator.isIdle()) {
            Thread.sleep(10);
        }
    }

    @Test
    public void actuatorHealth() throws Exception {
        given().port(port).log().all().when().get("/actuator/health/readiness").then().log().all().assertThat().statusCode(HttpStatus.SERVICE_UNAVAILABLE.value());
        waitForHealth();

        given().port(port).log().all().when().get("/actuator/health/readiness").then().log().all().assertThat().statusCode(HttpStatus.OK.value());
    }

}
