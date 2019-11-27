package org.entur.jwt.client.spring;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

import java.net.URI;

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
import static com.google.common.truth.Truth.*;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = "/application-keycloak.properties")
public class KeycloakClientTest {

    private MockRestServiceServer mockServer;

    @Autowired
    @Qualifier("jwtRestTemplate")
    private RestTemplate restTemplate;
    
	@Autowired
	private AccessTokenProvider accessTokenProvider;

	@Autowired
	private AccessTokenProviderHealthIndicator healthIndicator;

	@Value("classpath:keycloakClientCredentialsResponse.json")
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
		mockServer.expect(ExpectedCount.once(), 
		          requestTo(new URI("https://entur.org/auth/realms/myTenant/protocol/openid-connect/token")))
		          .andExpect(method(HttpMethod.POST))
		          .andRespond(withStatus(HttpStatus.OK)
		          .contentType(MediaType.APPLICATION_JSON)
		          .body(resource)
		        );
		AccessToken accessToken = accessTokenProvider.getAccessToken(false);
		
		assertThat(accessToken.getType()).isEqualTo("Bearer");
		assertThat(accessToken.getValue()).isEqualTo("x.y.z");
		assertThat(accessToken.getExpires()).isLessThan(System.currentTimeMillis() + 86400 * 1000);
		
	}
}
