package org.entur.jwt.client.spring.webflux;

import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
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
import org.springframework.core.io.Resource;
import org.springframework.test.context.TestPropertySource;

import java.io.IOException;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = "/application-keycloak.properties")
public class KeycloakClientTest {

    @Autowired
    private AccessTokenProvider accessTokenProvider;

    @Autowired
    private AccessTokenProviderHealthIndicator healthIndicator;

    @Value("classpath:keycloakClientCredentialsResponse.json")
    private Resource resource1;

    @Value("classpath:keycloakRefreshClientCredentialsResponse.json")
    private Resource resource2;

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
        mockWebServer.enqueue(AbstractActuatorTest.mockResponse(resource1));
        mockWebServer.enqueue(AbstractActuatorTest.mockResponse(resource2));

        AccessToken accessToken = accessTokenProvider.getAccessToken(false);

        assertThat(accessToken.getType()).isEqualTo("Bearer");
        assertThat(accessToken.getValue()).isEqualTo("x.y.z");
        assertThat(accessToken.getExpires()).isLessThan(System.currentTimeMillis() + 86400 * 1000 + 1);

        accessToken = accessTokenProvider.getAccessToken(true);

        RecordedRequest request1 = mockWebServer.takeRequest();
        assertTrue(request1.getPath().endsWith("/token"), request1.getPath());

        RecordedRequest request2 = mockWebServer.takeRequest();
        assertTrue(request2.getPath().endsWith("/token"), request2.getPath());
        assertTrue(request2.getBody().toString().contains("a.b.c"));

        assertThat(accessToken.getType()).isEqualTo("Bearer");
        assertThat(accessToken.getValue()).isEqualTo("a1.b1.c1");
        assertThat(accessToken.getExpires()).isLessThan(System.currentTimeMillis() + 86400 * 1000 + 1);
    }
}
