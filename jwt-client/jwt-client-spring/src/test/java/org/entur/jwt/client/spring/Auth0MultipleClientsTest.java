package org.entur.jwt.client.spring;

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
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

import static com.google.common.truth.Truth.assertThat;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = "/application-auth0-multiple.properties")
@DirtiesContext(classMode = ClassMode.BEFORE_EACH_TEST_METHOD)
public class Auth0MultipleClientsTest {

    private MockRestServiceServer mockServer;

    @LocalServerPort
    private int randomServerPort;
    
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

    @Value("classpath:auth0ClientCredentialsResponse1.json")
    private Resource resource1;

    @Value("classpath:auth0ClientCredentialsResponse2.json")
    private Resource resource2;

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
    public void testAccessToken() throws Exception {
        mockServer.expect(ExpectedCount.once(), requestTo(new URI("https://second.entur.org/oauth/token"))).andExpect(method(HttpMethod.POST)).andRespond(withStatus(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON).body(resource1));
        mockServer.expect(ExpectedCount.once(), requestTo(new URI("https://first.entur.org/oauth/token"))).andExpect(method(HttpMethod.POST)).andRespond(withStatus(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON).body(resource2));

        AccessToken accessToken1 = secondAccessTokenProvider.getAccessToken(false);

        assertThat(accessToken1.getType()).isEqualTo("Bearer");
        assertThat(accessToken1.getValue()).isEqualTo("a.b.c");

        AccessToken accessToken2 = firstAccessTokenProvider.getAccessToken(false);

        assertThat(accessToken2.getType()).isEqualTo("Bearer");
        assertThat(accessToken2.getValue()).isEqualTo("d.e.f");
    }   
    
    @Test
    public void testActuator() throws Exception {
        // down
        mockServer.expect(ExpectedCount.once(), requestTo(new URI("https://first.entur.org/oauth/token"))).andExpect(method(HttpMethod.POST)).andRespond(withStatus(HttpStatus.NOT_FOUND));
        mockServer.expect(ExpectedCount.once(), requestTo(new URI("https://second.entur.org/oauth/token"))).andExpect(method(HttpMethod.POST)).andRespond(withStatus(HttpStatus.NOT_FOUND));

        // up
        mockServer.expect(ExpectedCount.once(), requestTo(new URI("https://first.entur.org/oauth/token"))).andExpect(method(HttpMethod.POST)).andRespond(withStatus(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON).body(resource2));
        mockServer.expect(ExpectedCount.once(), requestTo(new URI("https://second.entur.org/oauth/token"))).andExpect(method(HttpMethod.POST)).andRespond(withStatus(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON).body(resource1));
        
        given().port(randomServerPort).log().all().when().get("/actuator/health/readiness").then().log().all().assertThat().statusCode(HttpStatus.SERVICE_UNAVAILABLE.value());
        given().port(randomServerPort).log().all().when().get("/actuator/health/readiness").then().log().all().assertThat().statusCode(HttpStatus.OK.value());
        
    }     
}
