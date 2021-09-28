package org.entur.jwt.spring.demo;

import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.spring.actuate.AccessTokenProviderHealthIndicator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;

import static com.google.common.truth.Truth.assertThat;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Testing using {@linkplain @Bean} overriding the bean id.
 */

@ActiveProfiles("mockJwt")
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class Auth0BeanTest {

    @LocalServerPort
    private int randomServerPort;
    
    @Autowired
    private AccessTokenProvider accessTokenProvider;

    @Autowired
    private AccessTokenProviderHealthIndicator healthIndicator;

    @Test
    public void contextLoads() {
        assertNotNull(accessTokenProvider);
        assertNotNull(healthIndicator);
    }

    @Test
    public void testAccessToken() throws Exception {
        // get token
        AccessToken accessToken = accessTokenProvider.getAccessToken(false);

        assertThat(accessToken.getType()).isEqualTo("Bearer");
        assertThat(accessToken.getValue()).isEqualTo("x.y.z");
    }
    
    @Test
    public void testActuator() throws Exception {
        given().port(randomServerPort).log().all().when().get("/actuator/health/readiness").then().log().all().assertThat().statusCode(HttpStatus.OK.value());
    }    

}
