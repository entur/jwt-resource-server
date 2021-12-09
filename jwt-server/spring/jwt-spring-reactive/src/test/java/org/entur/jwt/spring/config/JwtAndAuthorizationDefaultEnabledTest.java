package org.entur.jwt.spring.config;

import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.JwtWebSecurityAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test that context loads, and that the composite web security adapter is loaded
 */
@AuthorizationServer
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class JwtAndAuthorizationDefaultEnabledTest {

    @Test
    public void testContextLoads() {
    }

}
