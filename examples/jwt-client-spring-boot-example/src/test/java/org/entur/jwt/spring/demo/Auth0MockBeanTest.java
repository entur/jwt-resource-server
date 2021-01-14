package org.entur.jwt.spring.demo;

import static com.google.common.truth.Truth.assertThat;
import static io.restassured.RestAssured.given;
import static org.mockito.Mockito.when;

import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenHealth;
import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.spring.actuate.AccessTokenProviderHealthIndicator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;

/**
 * 
 * Testing using {@linkplain @MockBean}.
 * 
 */

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class Auth0MockBeanTest {

    @LocalServerPort
    private int randomServerPort;
    
    @MockBean
    private AccessTokenProvider accessTokenProvider;

    @MockBean
    private AccessTokenProviderHealthIndicator healthIndicator;

    @BeforeEach
    public void init() throws AccessTokenException {
        when(accessTokenProvider.getAccessToken(false)).thenReturn(new AccessToken("x.y.z", "Bearer", Long.MAX_VALUE));
        when(accessTokenProvider.getHealth(true)).thenReturn(new AccessTokenHealth(0, true));
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
