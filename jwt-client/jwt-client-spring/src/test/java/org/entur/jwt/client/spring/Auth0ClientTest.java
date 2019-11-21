package org.entur.jwt.client.spring;

import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.spring.actuate.AccessTokenProviderHealthIndicator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.TestPropertySource;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = "/application-auth0.properties")
public class Auth0ClientTest {

	@Autowired
	private AccessTokenProvider accessTokenProvider;
	
	@Autowired
	private AccessTokenProviderHealthIndicator healthIndicator;
	
	@Test
	public void contextLoads() {
		assertNotNull(accessTokenProvider);
		assertNotNull(healthIndicator);
	}
	
}
