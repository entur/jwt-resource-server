package org.entur.jwt.client.spring.cloud;

import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenHealth;
import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.spring.actuate.AccessTokenProviderHealthIndicator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;

import static com.google.common.truth.Truth.assertThat;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = "/application-auth0-single.properties")
@DirtiesContext(classMode = ClassMode.BEFORE_EACH_TEST_METHOD)
@ContextConfiguration(classes = {TestApplication.class, Auth0BeanTest.MyOverrideConfiguration.class})
public class Auth0BeanTest {

    @Configuration
    public static class MyOverrideConfiguration {

        @Bean
        public AccessTokenProvider myClient() throws AccessTokenException {
            AccessTokenProvider mock = mock(AccessTokenProvider.class);
            AccessToken value = new AccessToken("x.y.z", "Bearer", Long.MAX_VALUE);
            when(mock.getAccessToken(false)).thenReturn(value);
            when(mock.getAccessToken(true)).thenReturn(value);

            when(mock.getHealth(true)).thenReturn(new AccessTokenHealth(0, true));
            return mock;
        }
    }

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
