package org.entur.jwt.spring.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "entur.jwt.enabled=false",
        "management.endpoint.health.group.readiness.include=readinessState"
})
public class DisabledJwtTest {

    @Test
    public void testContextLoads() {
    }

}
