package org.entur.jwt.client.spring;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.spring.actuate.AccessTokenProviderHealthIndicator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.TestPropertySource;


@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(locations = "/application-keycloak.properties")
public class KeycloakClientTest {

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
