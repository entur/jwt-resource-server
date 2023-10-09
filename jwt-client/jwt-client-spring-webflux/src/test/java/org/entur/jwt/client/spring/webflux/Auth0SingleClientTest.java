package org.entur.jwt.client.spring.webflux;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.spring.actuate.AccessTokenProviderHealthIndicator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;

import static com.google.common.truth.Truth.assertThat;
import static io.restassured.RestAssured.given;
import static org.entur.jwt.client.spring.webflux.TestUtils.asString;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = "/application-auth0-single.properties")
@DirtiesContext(classMode = ClassMode.BEFORE_EACH_TEST_METHOD)
public class Auth0SingleClientTest {


    @LocalServerPort
    private int randomServerPort;

    @Autowired
    private AccessTokenProvider accessTokenProvider;

    @Autowired
    private AccessTokenProviderHealthIndicator healthIndicator;

    @Value("classpath:auth0ClientCredentialsResponse1.json")
    private Resource resource;

    private MockWebServer mockWebServer;

    @BeforeEach
    void setUp() throws IOException {
        mockWebServer = new MockWebServer();
        mockWebServer.start(8000);
        mockWebServer.url("/oauth/token");
    }

    @AfterEach
    void tearDown() throws IOException {
        mockWebServer.shutdown();
    }

    @Test
    public void contextLoads() {
        assertNotNull(accessTokenProvider);
        assertNotNull(healthIndicator);
    }

    @Test
    public void testAccessToken() throws Exception {
        mockWebServer.enqueue(new MockResponse().setBody(asString(resource)));

        // get token
        AccessToken accessToken = accessTokenProvider.getAccessToken(false);

        assertThat(accessToken.getType()).isEqualTo("Bearer");
        assertThat(accessToken.getValue()).isEqualTo("a.b.c");
        assertThat(accessToken.getExpires()).isLessThan(System.currentTimeMillis() + 86400 * 1000);
    }

    @Test
    public void testActuator() throws Exception {
        // down
        mockWebServer.enqueue(new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.value()));

        // up
        mockWebServer.enqueue(new MockResponse().setBody(asString(resource)));

        given().port(randomServerPort).log().all().when().get("/actuator/health/readiness").then().log().all().assertThat().statusCode(HttpStatus.SERVICE_UNAVAILABLE.value());
        given().port(randomServerPort).log().all().when().get("/actuator/health/readiness").then().log().all().assertThat().statusCode(HttpStatus.OK.value());

    }

}
