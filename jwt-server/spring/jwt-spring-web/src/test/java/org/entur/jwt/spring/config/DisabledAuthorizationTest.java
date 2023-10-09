package org.entur.jwt.spring.config;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@AuthorizationServer
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {"entur.authorization.enabled=false"})
public class DisabledAuthorizationTest {

    @Test
    public void testContextLoads() {
    }

}