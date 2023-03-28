package org.entur.jwt.spring.config;

import org.entur.jwt.junit5.AuthorizationServer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * Test that context loads
 */
@AuthorizationServer
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {"entur.jwt.enabled=true", "entur.authorization.enabled=true"})
public class JwtAndAuthorizationExplicityEnabledTest {

    /*
    @Autowired
    private WebSecurityConfigurerAdapter adapter;

    @Test
    public void testContextLoads() {
        assertTrue(adapter instanceof JwtWebSecurityChainConfiguration.CompositeWebSecurityConfigurerAdapter);
    }
*/
}