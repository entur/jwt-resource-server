package org.entur.jwt.jwk;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.only;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static com.google.common.truth.Truth.*;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.entur.jwt.jwk.AbstractCachedJwksProvider.JwkListCacheItem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.google.common.truth.Truth;

public class PreemptivceCachedJwksProviderTest extends AbstractDelegateProviderTest {

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

    private static final String KID = "NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg";

    private PreemptiveCachedJwksProvider<JwkImpl> provider;

    private DefaultJwkProvider<JwkImpl> wrapper;

    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        provider = new PreemptiveCachedJwksProvider<>(delegate, Duration.ofHours(10), Duration.ofSeconds(15), Duration.ofSeconds(10), false);

        wrapper = new DefaultJwkProvider<>(provider, new JwkFieldExtractorImpl());

    }

    @Test
    public void shouldUseFallbackWhenNotCached() throws Exception {
        when(delegate.getJwks(false)).thenReturn(jwks);
        assertThat(provider.getJwks(false), equalTo(jwks));
    }

    @Test
    public void shouldUseCachedValue() throws Exception {
        when(delegate.getJwks(false)).thenReturn(jwks).thenThrow(new JwkNotFoundException("TEST!", null));
        provider.getJwks(false);
        assertThat(provider.getJwks(false), equalTo(jwks));
        verify(delegate, only()).getJwks(false);
    }

    @Test
    public void shouldUseFallbackWhenExpiredCache() throws Exception {

        List<JwkImpl> first = Arrays.asList(jwk);
        List<JwkImpl> second = Arrays.asList(jwk, jwk);

        when(delegate.getJwks(false)).thenReturn(first).thenReturn(second);

        // first
        assertThat(provider.getJwks(false), equalTo(first));
        verify(delegate, only()).getJwks(false);

        // second
        assertThat(provider.getJwks(provider.getExpires(System.currentTimeMillis() + 1), false), equalTo(second));
        verify(delegate, times(2)).getJwks(false);
    }

    @Test
    public void shouldNotReturnExpiredValueWhenExpiredCacheAndRefreshFails() throws Exception {
        when(delegate.getJwks(false)).thenReturn(jwks).thenThrow(new JwkNotFoundException("TEST!", null));
        assertThat(provider.getJwks(false), equalTo(jwks));

        assertThrows(JwkNotFoundException.class, () -> {
            provider.getJwks(provider.getExpires(System.currentTimeMillis() + 1), false);
        });

    }

    @Test
    public void shouldGetBaseProvider() throws Exception {
        assertThat(provider.getProvider(), equalTo(delegate));
    }

    @Test
    public void shouldUseCachedValueForKnownKey() throws Exception {
        when(delegate.getJwks(false)).thenReturn(jwks).thenThrow(new JwkNotFoundException("TEST!", null));
        assertThat(wrapper.getJwk(KID), equalTo(jwk));
        verify(delegate, only()).getJwks(false);
    }

    @Test
    public void shouldRefreshCacheForUncachedKnownKey() throws Exception {
        JwkImpl a = mock(JwkImpl.class);
        when(a.getId()).thenReturn("a");
        JwkImpl b = mock(JwkImpl.class);
        when(b.getId()).thenReturn("b");

        List<JwkImpl> first = Arrays.asList(a);
        List<JwkImpl> second = Arrays.asList(b);

        when(delegate.getJwks(false)).thenReturn(first).thenReturn(second);

        // first
        assertThat(wrapper.getJwk("a"), equalTo(a));
        verify(delegate, only()).getJwks(false);

        // second
        assertThat(wrapper.getJwk("b"), equalTo(b));
        verify(delegate, times(2)).getJwks(false);
    }

    @Test
    public void shouldRefreshCacheAndThrowExceptionForUnknownKey() throws Exception {
        JwkImpl a = mock(JwkImpl.class);
        when(a.getId()).thenReturn("a");
        JwkImpl b = mock(JwkImpl.class);
        when(b.getId()).thenReturn("b");

        List<JwkImpl> first = Arrays.asList(a);
        List<JwkImpl> second = Arrays.asList(b);

        when(delegate.getJwks(false)).thenReturn(first).thenReturn(second);

        // first
        assertThat(wrapper.getJwk("a"), equalTo(a));
        verify(delegate, only()).getJwks(false);

        // second
        assertThrows(JwkNotFoundException.class, () -> {
            wrapper.getJwk("c");
        });
    }

    @Test
    public void shouldPreemptivelyRefreshCacheForKeys() throws Exception {
        JwkImpl a = mock(JwkImpl.class);
        when(a.getId()).thenReturn("a");
        JwkImpl b = mock(JwkImpl.class);
        when(b.getId()).thenReturn("b");

        List<JwkImpl> first = Arrays.asList(a);
        List<JwkImpl> second = Arrays.asList(b);

        when(delegate.getJwks(false)).thenReturn(first).thenReturn(second);

        // first jwks
        assertThat(wrapper.getJwk("a"), equalTo(a));
        verify(delegate, only()).getJwks(false);

        long justBeforeExpiry = provider.getExpires(System.currentTimeMillis()) - TimeUnit.SECONDS.toMillis(5);

        assertThat(provider.getJwks(justBeforeExpiry, false), equalTo(first)); // triggers a preemptive refresh attempt

        provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);
        verify(delegate, times(2)).getJwks(false);

        // second jwks
        assertThat(wrapper.getJwk("b"), equalTo(b)); // should already be in cache
        provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
        verify(delegate, times(2)).getJwks(false);
    }

    @Test
    public void shouldNotPreemptivelyRefreshCacheIfRefreshAlreadyInProgress() throws Exception {
        JwkImpl a = mock(JwkImpl.class);
        when(a.getId()).thenReturn("a");
        JwkImpl b = mock(JwkImpl.class);
        when(b.getId()).thenReturn("b");

        List<JwkImpl> first = Arrays.asList(a);
        List<JwkImpl> second = Arrays.asList(b);

        when(delegate.getJwks(false)).thenReturn(first).thenReturn(second);

        // first jwks
        assertThat(wrapper.getJwk("a"), equalTo(a));
        verify(delegate, only()).getJwks(false);

        JwkListCacheItem<JwkImpl> cache = provider.getCache(System.currentTimeMillis());

        long justBeforeExpiry = provider.getExpires(System.currentTimeMillis()) - TimeUnit.SECONDS.toMillis(5);

        assertThat(provider.getJwks(justBeforeExpiry, false), equalTo(first)); // triggers a preemptive refresh attempt

        provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

        provider.preemptiveRefresh(justBeforeExpiry, cache, false); // should not trigger a preemptive refresh attempt

        verify(delegate, times(2)).getJwks(false);

        // second jwks
        assertThat(wrapper.getJwk("b"), equalTo(b)); // should already be in cache
        provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
        verify(delegate, times(2)).getJwks(false);
    }

    @Test
    public void shouldFirePreemptivelyRefreshCacheAgainIfPreviousPreemptivelyRefreshAttemptFailed() throws Exception {
        JwkImpl a = mock(JwkImpl.class);
        when(a.getId()).thenReturn("a");
        JwkImpl b = mock(JwkImpl.class);
        when(b.getId()).thenReturn("b");

        List<JwkImpl> first = Arrays.asList(a);
        List<JwkImpl> second = Arrays.asList(b);

        when(delegate.getJwks(false)).thenReturn(first).thenThrow(new JwksUnavailableException("TEST!")).thenReturn(second);

        // first jwks
        assertThat(wrapper.getJwk("a"), equalTo(a));
        verify(delegate, only()).getJwks(false);

        long justBeforeExpiry = provider.getExpires(System.currentTimeMillis()) - TimeUnit.SECONDS.toMillis(5);

        assertThat(provider.getJwks(justBeforeExpiry, false), equalTo(first)); // triggers a preemptive refresh attempt

        provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

        assertThat(provider.getJwks(justBeforeExpiry, false), equalTo(first)); // triggers a another preemptive refresh attempt

        provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS);

        verify(delegate, times(3)).getJwks(false);

        // second jwks
        assertThat(wrapper.getJwk("b"), equalTo(b)); // should already be in cache
        provider.getExecutorService().awaitTermination(1, TimeUnit.SECONDS); // just to make sure
        verify(delegate, times(3)).getJwks(false);
    }

    @Test
    public void shouldAccceptIfAnotherThreadPreemptivelyUpdatesCache() throws Exception {
        when(delegate.getJwks(false)).thenReturn(jwks);

        provider.getJwks(false);

        long justBeforeExpiry = provider.getExpires(System.currentTimeMillis()) - TimeUnit.SECONDS.toMillis(5);

        ThreadHelper helper = new ThreadHelper().addRun(lockRunnable).addPause().addRun(unlockRunnable);
        try {
            helper.begin();

            provider.getJwks(justBeforeExpiry, false); // wants to update, but can't get lock

            verify(delegate, only()).getJwks(false);
        } finally {
            helper.close();
        }
    }

    @Test
    public void shouldSchedulePreemptivelyRefreshCacheForKeys() throws Exception {
        long timeToLive = 1000; 
        long refreshTimeout = 150;
        long preemptiveRefresh = 300;
        
        PreemptiveCachedJwksProvider provider = new PreemptiveCachedJwksProvider<>(delegate, Duration.ofMillis(timeToLive), Duration.ofMillis(refreshTimeout), Duration.ofMillis(preemptiveRefresh), true);
        DefaultJwkProvider wrapper = new DefaultJwkProvider<>(provider, new JwkFieldExtractorImpl());

        JwkImpl a = mock(JwkImpl.class);
        when(a.getId()).thenReturn("a");
        JwkImpl b = mock(JwkImpl.class);
        when(b.getId()).thenReturn("b");

        List<JwkImpl> first = Arrays.asList(a);
        List<JwkImpl> second = Arrays.asList(b);

        when(delegate.getJwks(false)).thenReturn(first).thenReturn(second);

        long time = System.currentTimeMillis();
        
        // first jwks
        assertThat(wrapper.getJwk("a"), equalTo(a));
        verify(delegate, only()).getJwks(false);

        ScheduledFuture<?> eagerJwkListCacheItem = provider.getEagerScheduledFuture();
        assertNotNull(eagerJwkListCacheItem);
        
        long left = eagerJwkListCacheItem.getDelay(TimeUnit.MILLISECONDS);
        
        long skew = System.currentTimeMillis() - time;
        
        Truth.assertThat(left).isAtMost(timeToLive - refreshTimeout - preemptiveRefresh);
        Truth.assertThat(left).isAtLeast(timeToLive - refreshTimeout - preemptiveRefresh - skew - 1);
        
        // sleep and check that keys were actually updated
        Thread.sleep(left + Math.min(25, 4 * skew));
        
        provider.getExecutorService().awaitTermination(Math.min(25, 4 * skew), TimeUnit.MILLISECONDS);
        verify(delegate, times(2)).getJwks(false);
        
        // no new update necessary
        assertThat(wrapper.getJwk("b"), equalTo(b));
        verify(delegate, times(2)).getJwks(false);
    }
}
