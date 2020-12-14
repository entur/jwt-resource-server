package org.entur.jwt.client;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.only;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.entur.jwt.client.AbstractCachedAccessTokenProvider.AccessTokenCacheItem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.google.common.truth.Truth;

public class PreemptivceCachedAccessTokenProviderTest extends AbstractDelegateProviderTest {

    private Runnable lockRunnable = new Runnable() {
        @Override
        public void run() {
            if (!provider.getLazyLock().tryLock()) {
                throw new RuntimeException();
            }
        }
    };

    private Runnable unlockRunnable = new Runnable() {
        @Override
        public void run() {
            provider.getLazyLock().unlock();
        }
    };

    private PreemptiveCachedAccessTokenProvider provider;

    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        provider = new PreemptiveCachedAccessTokenProvider(fallback, 10, TimeUnit.SECONDS, 15, TimeUnit.SECONDS, 15, TimeUnit.SECONDS, false);
    }

    @Test
    public void shouldUseFallbackWhenNotCached() throws Exception {
        assertThat(provider.getAccessToken(false)).isEqualTo(accessToken);
    }

    @Test
    public void shouldUseCachedValue() throws Exception {
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new AccessTokenException("TEST!", null));
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
        verify(fallback, only()).getAccessToken(false);
    }

    @Test
    public void shouldUseFallbackWhenExpiredCache() throws Exception {

        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenReturn(refreshedAccessToken);

        // first
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
        verify(fallback, only()).getAccessToken(false);

        // second
        assertThat(provider.getAccessToken(provider.getExpires(1), false)).isSameInstanceAs(refreshedAccessToken);
        verify(fallback, times(2)).getAccessToken(false);
    }

    @Test
    public void shouldNotReturnExpiredValueWhenExpiredCacheAndRefreshFails() throws Exception {
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new AccessTokenException("TEST!", null));
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);

        assertThrows(AccessTokenException.class, () -> {
            provider.getAccessToken(provider.getExpires(1), false);
        });
    }

    @Test
    public void shouldGetBaseProvider() throws Exception {
        assertThat(provider.getProvider()).isSameInstanceAs(fallback);
    }

    @Test
    public void shouldPreemptivelyRefreshCache() throws Exception {
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenReturn(refreshedAccessToken);

        // first access-token
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
        verify(fallback, only()).getAccessToken(false);

        long justBeforeExpiry = provider.getExpires(-TimeUnit.SECONDS.toMillis(5));

        assertThat(provider.getAccessToken(justBeforeExpiry, false)).isSameInstanceAs(accessToken); // triggers a preemptive refresh attempt

        provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);
        verify(fallback, times(2)).getAccessToken(false);

        // second
        assertThat(provider.getAccessToken(false)).isEqualTo(refreshedAccessToken); // should already be in cache
        provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
        verify(fallback, times(2)).getAccessToken(false);
    }

    @Test
    public void shouldNotPreemptivelyRefreshCacheIfRefreshAlreadyInProgress() throws Exception {
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenReturn(refreshedAccessToken);

        // first
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
        verify(fallback, only()).getAccessToken(false);

        AccessTokenCacheItem cache = provider.getCache();

        long justBeforeExpiry = provider.getExpires(-TimeUnit.SECONDS.toMillis(5));

        assertThat(provider.getAccessToken(justBeforeExpiry, false)).isSameInstanceAs(accessToken); // triggers a preemptive refresh attempt

        provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

        provider.preemptiveRefresh(justBeforeExpiry, cache, false); // should not trigger a preemptive refresh attempt

        verify(fallback, times(2)).getAccessToken(false);

        // second
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(refreshedAccessToken); // should already be in cache
        provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
        verify(fallback, times(2)).getAccessToken(false);
    }

    @Test
    public void shouldFirePreemptivelyRefreshCacheAgainIfPreviousPreemptivelyRefreshAttemptFailed() throws Exception {
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new AccessTokenUnavailableException("TEST!")).thenReturn(refreshedAccessToken);

        // first
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
        verify(fallback, only()).getAccessToken(false);

        long justBeforeExpiry = provider.getExpires(-TimeUnit.SECONDS.toMillis(5));

        assertThat(provider.getAccessToken(justBeforeExpiry, false)).isSameInstanceAs(accessToken); // triggers a preemptive refresh attempt

        provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

        assertThat(provider.getAccessToken(justBeforeExpiry, false)).isSameInstanceAs(accessToken); // triggers a another preemptive refresh attempt

        provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

        verify(fallback, times(3)).getAccessToken(false);

        // second
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(refreshedAccessToken); // should already be in cache
        provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
        verify(fallback, times(3)).getAccessToken(false);
    }

    @Test
    public void shouldAccceptIfAnotherThreadPreemptivelyUpdatesCache() throws Exception {
        provider.getAccessToken(false);

        long justBeforeExpiry = provider.getExpires(-TimeUnit.SECONDS.toMillis(5));

        ThreadHelper helper = new ThreadHelper().addRun(lockRunnable).addPause().addRun(unlockRunnable);
        try {
            helper.begin();

            provider.getAccessToken(justBeforeExpiry, false); // wants to update, but can't get lock

            verify(fallback, only()).getAccessToken(false);
        } finally {
            helper.close();
        }
    }
    
    @Test
    public void shouldSchedulePreemptivelyRefresh() throws Exception {
        long minimumTimeToLive = 1000; 
        long refreshTimeout = 150;
        long preemptiveRefresh = 1500;
        
        long validFor = 2000;
        
        long now = System.currentTimeMillis();

        fallback = mock(AccessTokenProvider.class);

        accessToken = new AccessToken("a.b.c", "bearer", now + validFor);
        refreshedAccessToken = new AccessToken("a.b.c", "bearer", now + 20 * 60 * 1000);

        provider = new PreemptiveCachedAccessTokenProvider(fallback, minimumTimeToLive, refreshTimeout, preemptiveRefresh, true);

        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenReturn(refreshedAccessToken);

        // first access-token
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
        verify(fallback, only()).getAccessToken(false);
        
        ScheduledFuture<?> eagerOnJwkListCacheItem = provider.getEagerScheduledFuture();
        assertNotNull(eagerOnJwkListCacheItem);
        
        long left = eagerOnJwkListCacheItem.getDelay(TimeUnit.MILLISECONDS);
        
        long skew = System.currentTimeMillis() - now;
        
        long limit = validFor - preemptiveRefresh - refreshTimeout;

        Truth.assertThat(left).isAtMost(limit);
        Truth.assertThat(left).isAtLeast(limit - skew);
        
        // sleep and check that keys were actually updated
        Thread.sleep(left + Math.min(25, 4 * skew));
        
        provider.getExecutorService().awaitTermination(Math.min(25, 4 * skew), TimeUnit.MILLISECONDS);
        verify(fallback, times(2)).getAccessToken(false);

        // second access-token
        // and that no new call was necessary
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(refreshedAccessToken);
        verify(fallback, times(2)).getAccessToken(false);
        
        
    }    
    
}
