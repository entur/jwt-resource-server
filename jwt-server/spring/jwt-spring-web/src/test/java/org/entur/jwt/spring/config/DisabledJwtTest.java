package org.entur.jwt.spring.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {"entur.jwt.enabled=false"})
public class DisabledJwtTest {

    @Autowired
    private WebSecurityConfigurerAdapter adapter;

    @Test
    public void testContextLoads() {
        assertTrue(adapter instanceof AuthorizationHttpSecurityConfigurer);
    }

}