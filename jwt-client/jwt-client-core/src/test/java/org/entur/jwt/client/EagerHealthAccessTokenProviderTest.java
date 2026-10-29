package org.entur.jwt.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
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

        assertTrue(provider.getHealth(false).isSuccess());

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
    public void shouldReturnBadHealthWhenAccessTokenFetchFailsAndCachedAccessTokenHasExpired() throws Exception {
        // the first two fetches return a short-lived access-token, the third fails and the fourth recovers
        AccessTokenProvider source = mock(AccessTokenProvider.class);
        AccessToken expiring = new AccessToken("a.b.c", "bearer", System.currentTimeMillis() + 1000);
        when(source.getAccessToken(false)).thenReturn(expiring, expiring).thenThrow(new AccessTokenException()).thenReturn(accessToken);
        EagerAccessTokenHealthProvider health = new EagerAccessTokenHealthProvider(source);
        // the cache is populated by the health refresh below
        health.setRefreshProvider(new DefaultCachedAccessTokenProvider(health, 0, 1000));

        // health is refreshed by the indicator before any access-token has been requested,
        // this puts the first (short-lived) access-token in the cache
        assertTrue(health.getHealth(true).isSuccess());
        assertTrue(health.getHealth(false).isSuccess());

        health.getAccessToken(false);
        assertTrue(health.getHealth(false).isSuccess());

        // the access-token, which is also the one held by the cache, is now expired
        sleepUntil(expiring.getExpires() + 100);

        assertThrows(AccessTokenException.class, () -> health.getAccessToken(false));

        // expected behavior: the latest call to the underlying provider failed and the
        // cached access-token is expired, so the previously refreshed (good) status no longer applies
        assertFalse(health.getHealth(false).isSuccess());

        // a refresh via the top-level provider recovers the health: the cache is expired,
        // so a new access-token is fetched from the underlying provider
        assertTrue(health.getHealth(true).isSuccess());
        assertTrue(health.getHealth(false).isSuccess());

        Mockito.verify(source, times(4)).getAccessToken(false);
    }

    @Test
    public void shouldReportGoodHealthWhenScheduledEagerRefreshFailedButCachedTokenIsStillValid() throws Exception {
        AccessTokenProvider source = mock(AccessTokenProvider.class);
        AccessToken shortLived = new AccessToken("a.b.c", "bearer", System.currentTimeMillis() + 3000);
        when(source.getAccessToken(false)).thenReturn(shortLived).thenThrow(new AccessTokenException());
        EagerAccessTokenHealthProvider health = new EagerAccessTokenHealthProvider(source);
        // real cache with eager (scheduled) refresh in front of the health provider
        try (PreemptiveCachedAccessTokenProvider cache = new PreemptiveCachedAccessTokenProvider(health, 100, 100, 2000, 0, true)) {
            health.setRefreshProvider(cache);
            health.setCacheMinimumTimeToLive(100);

            cache.getAccessToken(false);
            assertTrue(health.getHealth(true).isSuccess());

            // the scheduled refresh fires after roughly 900ms, and fails
            Mockito.verify(source, Mockito.timeout(3000).times(2)).getAccessToken(false);
            Thread.sleep(100);
            assertFalse(health.getCurrentHealth().isSuccess());

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

        when(fallback.getAccessToken(false)).thenThrow(new AccessTokenException());
        when(refreshProvider.getAccessToken(false)).thenAnswer(invocation -> {
            refreshStarted.countDown();
            failureRecorded.await();
            return refreshedAccessToken;
        });

        CompletableFuture<AccessTokenHealth> refresh = CompletableFuture.supplyAsync(() -> provider.getHealth(true));
        refreshStarted.await();

        // the underlying provider fails while the (good) refresh is in flight
        assertThrows(AccessTokenException.class, () -> provider.getAccessToken(false));
        failureRecorded.countDown();

        assertTrue(refresh.get().isSuccess());

        // the outdated good result must not shadow the newer failure
        assertFalse(provider.getHealth(false).isSuccess());
    }

    @Test
    public void shouldNotPublishRefreshFailureOverNewerSuccessfulFetch() throws Exception {
        CountDownLatch failureRecorded = new CountDownLatch(1);
        CountDownLatch successfulFetchCompleted = new CountDownLatch(1);

        when(fallback.getAccessToken(false)).thenThrow(new AccessTokenException()).thenReturn(accessToken);
        when(refreshProvider.getAccessToken(false)).thenAnswer(invocation -> {
            try {
                return provider.getAccessToken(false);
            } catch (AccessTokenException e) {
                failureRecorded.countDown();
                successfulFetchCompleted.await();
                throw e;
            }
        });

        CompletableFuture<AccessTokenHealth> refresh = CompletableFuture.supplyAsync(() -> provider.getHealth(true));
        failureRecorded.await();

        provider.getAccessToken(false);
        successfulFetchCompleted.countDown();

        assertFalse(refresh.get().isSuccess());
        assertTrue(provider.getHealth(false).isSuccess());
    }

}
