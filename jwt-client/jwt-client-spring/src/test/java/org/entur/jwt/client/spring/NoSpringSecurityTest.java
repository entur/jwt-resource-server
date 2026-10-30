package org.entur.jwt.client.spring;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.util.ClassUtils;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Regression test: a servlet application without Spring Security which adds this module (only to call a downstream API)
 * must not get Spring Security transitively, as that activates Spring Boot's default security filter chain
 * (form login / basic authentication) for every endpoint.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = "/application-auth0-single.properties")
@ContextConfiguration(classes = TestApplication.class)
public class NoSpringSecurityTest {

    @LocalServerPort
    private int randomServerPort;

    @Autowired
    private ApplicationContext applicationContext;

    @Test
    public void shouldNotHaveSpringSecurityOnClasspath() {
        assertFalse(ClassUtils.isPresent("org.springframework.security.web.SecurityFilterChain", getClass().getClassLoader()));
    }

    @Test
    public void shouldNotRegisterSpringSecurityFilterChain() {
        assertFalse(applicationContext.containsBean("springSecurityFilterChain"));
    }

    @Test
    public void shouldNotRequireAuthentication() {
        given().port(randomServerPort).redirects().follow(false).log().all().when().get("/actuator/info").then().log().all().assertThat().statusCode(HttpStatus.OK.value());
    }
}
