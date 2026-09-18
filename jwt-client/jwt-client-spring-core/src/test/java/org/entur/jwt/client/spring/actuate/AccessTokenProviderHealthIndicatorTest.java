package org.entur.jwt.client.spring.actuate;

import org.entur.jwt.client.AccessTokenHealth;
import org.entur.jwt.client.AccessTokenHealthProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AccessTokenProviderHealthIndicatorTest {

    private ExecutorService executor;

    @AfterEach
    public void tearDown() {
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    private AccessTokenProviderHealthIndicator newIndicator() {
        executor = Executors.newSingleThreadExecutor();
        return new AccessTokenProviderHealthIndicator(executor, "myProvider");
    }

    private static void waitUntilIdle(AccessTokenProviderHealthIndicator indicator) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 2000;
        while (System.currentTimeMillis() < deadline && !indicator.isIdle()) {
            Thread.sleep(10);
        }
    }

    @Test
    public void testHealthyProviderReportsUpWithoutBackgroundRefresh() {
        AccessTokenProviderHealthIndicator indicator = newIndicator();

        AccessTokenHealthProvider provider = mock(AccessTokenHealthProvider.class);
        when(provider.getHealth(false)).thenReturn(new AccessTokenHealth(System.currentTimeMillis(), true));

        indicator.addHealthIndicators("a", provider);

        Health health = indicator.health();

        assertEquals(Status.UP, health.getStatus());
        verify(provider, times(0)).getHealth(true);
    }

    @Test
    public void testUnhealthyProviderRecoversInBackground() throws InterruptedException {
        AccessTokenProviderHealthIndicator indicator = newIndicator();

        AtomicBoolean refreshed = new AtomicBoolean(false);
        AccessTokenHealthProvider provider = mock(AccessTokenHealthProvider.class);
        when(provider.getHealth(false)).thenAnswer(invocation ->
                new AccessTokenHealth(System.currentTimeMillis(), refreshed.get()));
        when(provider.getHealth(true)).thenAnswer(invocation -> {
            refreshed.set(true);
            return new AccessTokenHealth(System.currentTimeMillis(), true);
        });

        indicator.addHealthIndicators("a", provider);

        // first check: unhealthy, triggers background refresh
        assertEquals(Status.DOWN, indicator.health().getStatus());

        waitUntilIdle(indicator);

        // second check: background refresh has completed, now healthy
        assertEquals(Status.UP, indicator.health().getStatus());

        verify(provider, times(1)).getHealth(true);
    }

    @Test
    public void testProviderExceptionOnHealthCheckIsTreatedAsUnhealthy() {
        AccessTokenProviderHealthIndicator indicator = newIndicator();

        AccessTokenHealthProvider provider = mock(AccessTokenHealthProvider.class);
        when(provider.getHealth(false)).thenThrow(new RuntimeException("boom"));
        when(provider.getHealth(true)).thenThrow(new RuntimeException("boom"));

        indicator.addHealthIndicators("a", provider);

        assertEquals(Status.DOWN, indicator.health().getStatus());
    }

    @Test
    public void testDoesNotStartConcurrentRefreshWhileOneIsInProgress() throws InterruptedException {
        AccessTokenProviderHealthIndicator indicator = newIndicator();

        CountDownLatch refreshStarted = new CountDownLatch(1);
        CountDownLatch finishRefresh = new CountDownLatch(1);
        AccessTokenHealthProvider slowProvider = mock(AccessTokenHealthProvider.class);
        when(slowProvider.getHealth(false)).thenReturn(new AccessTokenHealth(System.currentTimeMillis(), false));
        when(slowProvider.getHealth(true)).thenAnswer(invocation -> {
            refreshStarted.countDown();
            finishRefresh.await();
            return new AccessTokenHealth(System.currentTimeMillis(), true);
        });

        indicator.addHealthIndicators("a", slowProvider);

        // triggers a background refresh that remains blocked until the second health check
        assertEquals(Status.DOWN, indicator.health().getStatus());
        assertTrue(refreshStarted.await(2, TimeUnit.SECONDS));
        // called again while the previous refresh is still running: must not start a second one
        assertEquals(Status.DOWN, indicator.health().getStatus());
        finishRefresh.countDown();

        waitUntilIdle(indicator);

        verify(slowProvider, times(1)).getHealth(true);
    }

    @Test
    public void testCloseShutsDownExecutor() {
        AccessTokenProviderHealthIndicator indicator = newIndicator();

        indicator.close();

        assertEquals(true, executor.isShutdown());
    }
}
