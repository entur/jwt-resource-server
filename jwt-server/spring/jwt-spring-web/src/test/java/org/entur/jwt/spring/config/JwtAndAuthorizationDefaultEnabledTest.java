package org.entur.jwt.spring.config;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Test that context loads
 */
@AuthorizationServer
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class JwtAndAuthorizationDefaultEnabledTest {

    @Test
    public void testContextLoads() {
    }

}
