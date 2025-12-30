package org.entur.jwt.client.spring.resttemplate;

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
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

import static com.google.common.truth.Truth.assertThat;
import static org.hamcrest.Matchers.any;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.headerDoesNotExist;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = "/application-generic-oauth2.properties")
public class GenericClientTest {
    private MockRestServiceServer mockServer;

    @Autowired
    @Qualifier("jwtRestTemplate")
    private RestTemplate restTemplate;

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

    @BeforeEach
    public void beforeEach() {
        mockServer = MockRestServiceServer.bindTo(restTemplate).build();
    }

    @AfterEach
    public void afterEach() {
        mockServer.verify();
    }

    @Test
    public void contextLoads() {
        assertNotNull(firstAccessTokenProvider);
        assertNotNull(secondAccessTokenProvider);
        assertNotNull(healthIndicator);
    }

    @Test
    public void testAccessTokenWithClientSecretInRequestUrlParameters() throws Exception {
        mockServer
                .expect(ExpectedCount.once(), requestTo(new URI("http://localhost:8000/v1/oauth/token")))
                .andExpect(method(HttpMethod.POST))
                .andExpect(headerDoesNotExist("Authorization"))
                .andRespond(withStatus(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON).body(resource));

        AccessToken accessToken = firstAccessTokenProvider.getAccessToken(false);

        assertThat(accessToken.getType()).isEqualTo("Bearer");
        assertThat(accessToken.getValue()).isEqualTo("x.y.z");
        assertThat(accessToken.getExpires()).isLessThan(System.currentTimeMillis() + 86400 * 1000 + 1);
    }

    @Test
    public void testAccessTokenWithClientSecretInRequestAuthorizationHeader() throws Exception {
        mockServer
                .expect(ExpectedCount.once(), requestTo(new URI("http://localhost:8001/v1/oauth/token")))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("Authorization", any(String.class)))
                .andRespond(withStatus(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON).body(resource));

        AccessToken accessToken = secondAccessTokenProvider.getAccessToken(false);

        assertThat(accessToken.getType()).isEqualTo("Bearer");
        assertThat(accessToken.getValue()).isEqualTo("x.y.z");
        assertThat(accessToken.getExpires()).isLessThan(System.currentTimeMillis() + 86400 * 1000 + 1);
    }
}
