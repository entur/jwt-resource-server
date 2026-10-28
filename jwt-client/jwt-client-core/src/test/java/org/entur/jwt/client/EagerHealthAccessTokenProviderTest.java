package org.entur.jwt.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.entur.jwt.client.ScriptedAccessTokenProvider.failure;
import static org.entur.jwt.client.ScriptedAccessTokenProvider.tokenExpiringIn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

public class EagerHealthAccessTokenProviderTest extends AbstractDelegateProviderTest {

    private EagerAccessTokenHealthProvider provider;
    private AccessTokenProvider refreshProvider;
    
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        provider = new EagerAccessTokenHealthProvider(fallback);
        refreshProvider = mock(AccessTokenProvider.class);
        provider.setRefreshProvider(refreshProvider);
        when(refreshProvider.getAccessToken(false)).thenReturn(refreshedAccessToken);
        when(refreshProvider.getAccessToken(true)).thenReturn(refreshedAccessToken);
    }
    
    @Test
    public void shouldReturnUnknownHealthIfNoPreviousStatusAndRefreshingIsNotAllowed() throws Exception {
        AccessTokenHealth health = provider.getHealth(false);
        assertNull(health);

        // expected behavior: the health provider did not attempt to refresh status.
        Mockito.verify(refreshProvider, times(0)).getAccessToken(false);
        Mockito.verify(fallback, times(0)).getAccessToken(false);
    }

    @Test
    public void shouldReturnGoodHealth() throws Exception {
        when(fallback.getAccessToken(false)).thenReturn(accessToken);

        // attempt to get jwks
        provider.getAccessToken(false);

        AccessTokenHealth health1 = provider.getHealth(true);
        assertTrue(health1.isSuccess());

        AccessTokenHealth health2 = provider.getHealth(false);
        assertSame(health1, health2);

        // expected behavior: the health provider attempted to refresh
        // a good health status.
        Mockito.verify(fallback, times(1)).getAccessToken(false);
        Mockito.verify(refreshProvider, times(1)).getAccessToken(false);
    }

    @Test
    public void shouldReturnGoodHealthIfAccessTokenCouldBeRefreshedAfterBadStatus() throws Exception {
        when(fallback.getAccessToken(false)).thenThrow(new AccessTokenException());

        // attempt to get jwks
        assertThrows(AccessTokenException.class, () -> {
            provider.getAccessToken(false);
        });

        AccessTokenHealth health = provider.getHealth(true);
        assertTrue(health.isSuccess());

        // expected behavior: the health provider refreshed
        // a bad health status.
        Mockito.verify(fallback, times(1)).getAccessToken(false);
        Mockito.verify(refreshProvider, times(1)).getAccessToken(false);
    }    

    @Test
    public void shouldReturnBadHealthIfAccessTokenCouldNotBeRefreshedAfterBadStatus() throws Exception {
        when(fallback.getAccessToken(false)).thenThrow(new AccessTokenException());
        when(refreshProvider.getAccessToken(false)).thenThrow(new AccessTokenException());

        // attempt to get access-token
        assertThrows(AccessTokenException.class, () -> {
            provider.getAccessToken(false);
        });

        AccessTokenHealth health = provider.getHealth(true);
        assertFalse(health.isSuccess());

        // expected behavior: the health provider refreshed
        // a bad health status.
        Mockito.verify(fallback, times(1)).getAccessToken(false);
        Mockito.verify(refreshProvider, times(1)).getAccessToken(false);
    }    
  

    @Test
    public void shouldRecoverFromBadHealth() throws Exception {
        when(fallback.getAccessToken(false)).thenThrow(new AccessTokenException()) // fail
                .thenReturn(accessToken); // recover

        // trigger fail
        assertThrows(AccessTokenException.class, () -> {
            provider.getAccessToken(false);
        });
        provider.getAccessToken(false);

        AccessTokenHealth health2 = provider.getHealth(true);
        assertTrue(health2.isSuccess());

        AccessTokenHealth health1 = provider.getHealth(false);
        assertTrue(health1.isSuccess());
        
        Mockito.verify(fallback, times(2)).getAccessToken(false);
        Mockito.verify(refreshProvider, times(1)).getAccessToken(false);
    }

    @Test
    public void shouldLetFailedAccessTokenFetchSupersedeRefreshedGoodHealth() throws Exception {
        // the access-token expires before the failure, so no valid access-token is available
        ScriptedAccessTokenProvider source = new ScriptedAccessTokenProvider(tokenExpiringIn(50), tokenExpiringIn(50), failure(), tokenExpiringIn(600_000));
        EagerAccessTokenHealthProvider health = new EagerAccessTokenHealthProvider(source);
        health.setRefreshProvider(new DefaultCachedAccessTokenProvider(health, 0, 1000));

        // health is refreshed by the indicator before any access-token has been requested
        assertTrue(health.getHealth(true).isSuccess());
        assertTrue(health.getHealth(false).isSuccess());

        health.getAccessToken(false);
        assertTrue(health.getHealth(false).isSuccess());

        Thread.sleep(100);

        assertThrows(AccessTokenException.class, () -> health.getAccessToken(false));

        // expected behavior: the latest call to the underlying provider failed, so
        // the previously refreshed (good) status no longer applies
        assertFalse(health.getHealth(false).isSuccess());

        // a refresh via the top-level provider recovers the health
        assertTrue(health.getHealth(true).isSuccess());
        assertTrue(health.getHealth(false).isSuccess());

        assertEquals(4, source.getCalls());
    }

    @Test
    public void shouldReportGoodHealthWhenScheduledEagerRefreshFailedButCachedTokenIsStillValid() throws Exception {
        ScriptedAccessTokenProvider source = new ScriptedAccessTokenProvider(tokenExpiringIn(2000), failure());
        EagerAccessTokenHealthProvider health = new EagerAccessTokenHealthProvider(source);
        // real cache with eager (scheduled) refresh in front of the health provider
        try (PreemptiveCachedAccessTokenProvider cache = new PreemptiveCachedAccessTokenProvider(health, 100, 100, 1000, 0, true)) {
            health.setRefreshProvider(cache);
            health.setCacheMinimumTimeToLive(100);

            cache.getAccessToken(false);
            assertTrue(health.getHealth(true).isSuccess());

            // the scheduled refresh fires after roughly 900ms, and fails
            long deadline = System.currentTimeMillis() + 3000;
            while (source.getCalls() < 2 && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertEquals(2, source.getCalls());
            Thread.sleep(100);

            // a valid access-token is available from the cache, so health is good
            // even before health is refreshed
            assertTrue(health.getHealth(false).isSuccess());
            assertTrue(health.getHealth(true).isSuccess());
            assertTrue(health.getHealth(false).isSuccess());
        }
    }

    @Test
    public void shouldNotPublishStaleStatusWhenUnderlyingProviderFailsDuringRefresh() throws Exception {
        CountDownLatch refreshStarted = new CountDownLatch(1);
        CountDownLatch failureRecorded = new CountDownLatch(1);

        EagerAccessTokenHealthProvider health = new EagerAccessTokenHealthProvider(new ScriptedAccessTokenProvider(failure()));
        health.setRefreshProvider(new ScriptedAccessTokenProvider(tokenExpiringIn(600_000)).beforeEachCall(() -> {
            refreshStarted.countDown();
            try {
                failureRecorded.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }));

        CompletableFuture<AccessTokenHealth> refresh = CompletableFuture.supplyAsync(() -> health.getHealth(true));
        refreshStarted.await();

        // the underlying provider fails while the (good) refresh is in flight
        assertThrows(AccessTokenException.class, () -> health.getAccessToken(false));
        failureRecorded.countDown();

        assertTrue(refresh.get().isSuccess());

        // the outdated good result must not shadow the newer failure
        assertFalse(health.getHealth(false).isSuccess());
    }

}
