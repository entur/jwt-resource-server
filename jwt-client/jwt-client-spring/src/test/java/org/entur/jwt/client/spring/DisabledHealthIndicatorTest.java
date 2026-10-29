package org.entur.jwt.client.spring;

import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.spring.actuate.AccessTokenProviderHealthIndicator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

@SpringBootTest
// note: the test configuration includes the health indicator in the readiness group
@TestPropertySource(locations = "/application-auth0-single.properties", properties = {"management.health.jwts.enabled=false", "management.endpoint.health.validate-group-membership=false"})
@ContextConfiguration(classes = TestApplication.class)
public class DisabledHealthIndicatorTest {

    @Autowired
    private AccessTokenProvider accessTokenProvider;

    @Autowired
    private ObjectProvider<AccessTokenProviderHealthIndicator> healthIndicator;

    @Test
    public void shouldNotAddHealthIndicator() {
        assertNotNull(accessTokenProvider);
        assertNull(healthIndicator.getIfAvailable());
    }
}
