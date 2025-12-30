package org.entur.jwt.client.spring;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.spring.actuate.AccessTokenProviderHealthIndicator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.core.io.Resource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.client.RestClient;

import java.io.IOException;

import static com.google.common.truth.Truth.assertThat;
import static org.entur.jwt.client.spring.AbstractActuatorTest.asString;
import static org.entur.jwt.client.spring.AbstractActuatorTest.mockResponse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = "/application-generic-oauth2.properties")
public class GenericClientTest {

    @Autowired
    @Qualifier("jwtRestClient")
    private RestClient restClient;

    @Autowired
    @Qualifier("firstClient")
    private AccessTokenProvider firstAccessTokenProvider;

    @Autowired
    @Qualifier("secondClient")
    private AccessTokenProvider secondAccessTokenProvider;

    @Autowired
    private AccessTokenProviderHealthIndicator healthIndicator;

    @Value("classpath:genericOAuth2ClientCredentialsResponse.json")
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
        assertNotNull(firstAccessTokenProvider);
        assertNotNull(secondAccessTokenProvider);
        assertNotNull(healthIndicator);
    }

    @Test
    public void testAccessTokenWithClientSecretInRequestUrlParameters() throws Exception {

        MockResponse mockResponse = new MockResponse();
        mockResponse.setBody(asString(resource));
        mockResponse.setHeader("Content-Type", "application/json");

        mockWebServer.enqueue(mockResponse(resource));

        AccessToken accessToken = firstAccessTokenProvider.getAccessToken(false);

        assertThat(accessToken.getType()).isEqualTo("Bearer");
        assertThat(accessToken.getValue()).isEqualTo("x.y.z");
        assertThat(accessToken.getExpires()).isLessThan(System.currentTimeMillis() + 86400 * 1000 + 1);

        RecordedRequest request1 = mockWebServer.takeRequest();
        assertNull(request1.getHeaders().get("Authorization"));
    }

    @Test
    public void testAccessTokenWithClientSecretInRequestAuthorizationHeader() throws Exception {

        mockWebServer.enqueue(mockResponse(resource));
        AccessToken accessToken = secondAccessTokenProvider.getAccessToken(false);

        assertThat(accessToken.getType()).isEqualTo("Bearer");
        assertThat(accessToken.getValue()).isEqualTo("x.y.z");
        assertThat(accessToken.getExpires()).isLessThan(System.currentTimeMillis() + 86400 * 1000 + 1);

        RecordedRequest request1 = mockWebServer.takeRequest();
        assertNotNull(request1.getHeaders().get("Authorization"));
    }
}
