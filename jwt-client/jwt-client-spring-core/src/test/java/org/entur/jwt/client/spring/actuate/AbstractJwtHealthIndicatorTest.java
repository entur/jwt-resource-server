package org.entur.jwt.client.spring.actuate;

import org.entur.jwt.client.AccessTokenHealth;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AbstractJwtHealthIndicatorTest {

    private static class TestJwtHealthIndicator extends AbstractJwtHealthIndicator {

        private AccessTokenHealth health;

        protected TestJwtHealthIndicator(String name) {
            super(name);
        }

        public void setHealth(AccessTokenHealth health) {
            this.health = health;
        }

        @Override
        protected AccessTokenHealth refreshHealth() {
            return health;
        }
    }

    @Test
    public void testInitializedUp() {
        TestJwtHealthIndicator indicator = new TestJwtHealthIndicator("myProvider");
        indicator.setHealth(new AccessTokenHealth(System.currentTimeMillis(), true));

        Health health = indicator.health();

        assertEquals(Status.UP, health.getStatus());
    }

    @Test
    public void testInitializedDown() {
        TestJwtHealthIndicator indicator = new TestJwtHealthIndicator("myProvider");
        indicator.setHealth(new AccessTokenHealth(System.currentTimeMillis(), false));

        Health health = indicator.health();

        assertEquals(Status.DOWN, health.getStatus());
    }

    @Test
    public void testTransitionsFromDownToUp() {
        TestJwtHealthIndicator indicator = new TestJwtHealthIndicator("myProvider");

        indicator.setHealth(new AccessTokenHealth(System.currentTimeMillis(), false));
        assertEquals(Status.DOWN, indicator.health().getStatus());

        indicator.setHealth(new AccessTokenHealth(System.currentTimeMillis(), true));
        assertEquals(Status.UP, indicator.health().getStatus());
    }

    @Test
    public void testTransitionsFromUpToDown() {
        TestJwtHealthIndicator indicator = new TestJwtHealthIndicator("myProvider");

        indicator.setHealth(new AccessTokenHealth(System.currentTimeMillis(), true));
        assertEquals(Status.UP, indicator.health().getStatus());

        indicator.setHealth(new AccessTokenHealth(System.currentTimeMillis(), false));
        assertEquals(Status.DOWN, indicator.health().getStatus());
    }

    @Test
    public void testUnknownWhenNoHealthAvailable() {
        TestJwtHealthIndicator indicator = new TestJwtHealthIndicator("myProvider");
        indicator.setHealth(null);

        Health health = indicator.health();

        assertEquals(Status.UNKNOWN, health.getStatus());
    }

    @Test
    public void testGetName() {
        TestJwtHealthIndicator indicator = new TestJwtHealthIndicator("myProvider");

        assertEquals("myProvider", indicator.getName());
    }
}
