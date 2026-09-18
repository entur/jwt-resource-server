package org.entur.jwt.spring.actuate;

import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AbstractJwksHealthIndicatorTest {

    private static class TestJwksHealthIndicator extends AbstractJwksHealthIndicator {

        private JwksHealth nextHealth;

        TestJwksHealthIndicator(String name) {
            super(name);
        }

        void setNextHealth(JwksHealth nextHealth) {
            this.nextHealth = nextHealth;
        }

        @Override
        protected JwksHealth getJwksHealth() {
            return nextHealth;
        }
    }

    @Test
    void reportsUpWhenHealthy() {
        TestJwksHealthIndicator indicator = new TestJwksHealthIndicator("my-tenant");
        indicator.setNextHealth(new JwksHealth(System.currentTimeMillis(), true));

        Health health = indicator.health();

        assertEquals(Status.UP, health.getStatus());
        assertNotNull(health.getDetails().get("timestamp"));
    }

    @Test
    void reportsDownWhenUnhealthy() {
        TestJwksHealthIndicator indicator = new TestJwksHealthIndicator("my-tenant");
        indicator.setNextHealth(new JwksHealth(System.currentTimeMillis(), false));

        Health health = indicator.health();

        assertEquals(Status.DOWN, health.getStatus());
    }

    @Test
    void reportsUnknownWhenNoHealthAvailable() {
        TestJwksHealthIndicator indicator = new TestJwksHealthIndicator("my-tenant");
        indicator.setNextHealth(null);

        Health health = indicator.health();

        assertEquals(Status.UNKNOWN, health.getStatus());
    }

    @Test
    void exposesName() {
        TestJwksHealthIndicator indicator = new TestJwksHealthIndicator("my-tenant");
        assertEquals("my-tenant", indicator.getName());
    }
}
