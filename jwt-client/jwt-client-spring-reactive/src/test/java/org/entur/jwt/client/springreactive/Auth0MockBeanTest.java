package org.entur.jwt.client.springreactive;

import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenHealth;
import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.springreactive.actuate.AccessTokenProviderHealthIndicator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.ContextConfiguration;

import static com.google.common.truth.Truth.assertThat;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@DirtiesContext(classMode = ClassMode.BEFORE_EACH_TEST_METHOD)
@ContextConfiguration(classes = {TestApplication.class})
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
