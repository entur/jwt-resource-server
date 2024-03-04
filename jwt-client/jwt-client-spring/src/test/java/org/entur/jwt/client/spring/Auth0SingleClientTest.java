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
import org.springframework.boot.test.web.server.LocalServerPort;
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
@TestPropertySource(locations = "/application-auth0-single.properties")
@DirtiesContext(classMode = ClassMode.BEFORE_EACH_TEST_METHOD)
public class Auth0SingleClientTest extends AbstractActuatorTest {

    private MockRestServiceServer mockServer;

    @LocalServerPort
    private int randomServerPort;
    
    @Autowired
    @Qualifier("jwtRestTemplate")
    private RestTemplate restTemplate;

    @Autowired
    private AccessTokenProvider accessTokenProvider;

    @Autowired
    private AccessTokenProviderHealthIndicator healthIndicator;

    @Value("classpath:auth0ClientCredentialsResponse1.json")
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
        assertNotNull(accessTokenProvider);
        assertNotNull(healthIndicator);
    }

    @Test
    public void testAccessToken() throws Exception {
        mockServer.expect(ExpectedCount.once(), requestTo(new URI("https://my.entur.org/oauth/token"))).andExpect(method(HttpMethod.POST)).andRespond(withStatus(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON).body(resource));
        
        // get token
        AccessToken accessToken = accessTokenProvider.getAccessToken(false);

        assertThat(accessToken.getType()).isEqualTo("Bearer");
        assertThat(accessToken.getValue()).isEqualTo("a.b.c");
        assertThat(accessToken.getExpires()).isLessThan(System.currentTimeMillis() + 86400 * 1000 + 1);
    }
    
    @Test
    public void testActuator() throws Exception {
        // down
        mockServer.expect(ExpectedCount.twice(), requestTo(new URI("https://my.entur.org/oauth/token"))).andExpect(method(HttpMethod.POST)).andRespond(withStatus(HttpStatus.NOT_FOUND));

        // up
        mockServer.expect(ExpectedCount.once(), requestTo(new URI("https://my.entur.org/oauth/token"))).andExpect(method(HttpMethod.POST)).andRespond(withStatus(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON).body(resource));
        
        given().port(randomServerPort).log().all().when().get("/actuator/health/readiness").then().log().all().assertThat().statusCode(HttpStatus.SERVICE_UNAVAILABLE.value());
        waitForHealth();

        given().port(randomServerPort).log().all().when().get("/actuator/health/readiness").then().log().all().assertThat().statusCode(HttpStatus.SERVICE_UNAVAILABLE.value());
        waitForHealth();

        given().port(randomServerPort).log().all().when().get("/actuator/health/readiness").then().log().all().assertThat().statusCode(HttpStatus.OK.value());
        
    }    

}
