package org.entur.jwt.jwk;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.only;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.Thread.State;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DefaultCachedJwksProviderTest extends AbstractDelegateProviderTest {

    private Runnable lockRunnable = new Runnable() {
        @Override
        public void run() {
            if (!provider.getLock().tryLock()) {
                throw new RuntimeException();
            }
        }
    };

    private Runnable unlockRunnable = new Runnable() {
        @Override
        public void run() {
            provider.getLock().unlock();
        }
    };

    private DefaultCachedJwksProvider<JwkImpl> provider;

    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        provider = new DefaultCachedJwksProvider<>(delegate, Duration.ofHours(10), Duration.ofSeconds(2));
    }

    @Test
    public void shouldUseDelegateWhenNotCached() throws Exception {
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
    public void shouldUseDelegateWhenExpiredCache() throws Exception {

        List<JwkImpl> first = Arrays.asList(jwk);
        List<JwkImpl> second = Arrays.asList(jwk, jwk);

        when(delegate.getJwks(false)).thenReturn(first).thenReturn(second);

        // first
        provider.getJwks(false);
        assertThat(provider.getJwks(false), equalTo(first));
        verify(delegate, only()).getJwks(false);

        // second
        provider.getJwks(provider.getExpires(System.currentTimeMillis() + 1), false);
        assertThat(provider.getJwks(false), equalTo(second));
        verify(delegate, times(2)).getJwks(false);
    }

    @Test
    public void shouldNotReturnExpiredValueWhenExpiredCache() throws Exception {
        when(delegate.getJwks(false)).thenReturn(jwks).thenThrow(new JwkNotFoundException("TEST!", null));
        provider.getJwks(false);
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
        DefaultJwkProvider<JwkImpl> wrapper = new DefaultJwkProvider<>(provider, new JwkFieldExtractorImpl());
        wrapper.getJwk(KID);
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

        DefaultJwkProvider<JwkImpl> keyProvider = new DefaultJwkProvider<>(provider, fieldExtractor);
        // first
        assertThat(keyProvider.getJwk("a"), equalTo(a));
        verify(delegate, only()).getJwks(false);

        // second
        assertThat(keyProvider.getJwk("b"), equalTo(b));
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

        DefaultJwkProvider<JwkImpl> wrapper = new DefaultJwkProvider<>(provider, new JwkFieldExtractorImpl());

        // first
        assertThat(wrapper.getJwk("a"), equalTo(a));
        verify(delegate, only()).getJwks(false);

        // second
        assertThrows(JwkNotFoundException.class, () -> {
            wrapper.getJwk("c");
        });
    }

    @Test
    public void shouldThrowExceptionIfAnotherThreadBlocksUpdate() throws Exception {
        ThreadHelper helper = new ThreadHelper().addRun(lockRunnable).addPause().addRun(unlockRunnable);
        try {
            helper.start();
            while (helper.getState() != State.WAITING) {
                Thread.yield();
            }

            assertThrows(JwksUnavailableException.class, () -> {
                provider.getJwks(false);
            });
        } finally {
            helper.close();
        }
    }

    @Test
    public void shouldAccceptIfAnotherThreadUpdatesCache() throws Exception {
        Runnable racer = new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(1000);
                    provider.getJwks(false);
                } catch (Exception e) {
                    throw new RuntimeException();
                }
            }
        };

        when(delegate.getJwks(false)).thenReturn(jwks);

        ThreadHelper helper = new ThreadHelper().addRun(lockRunnable).addPause().addRun(racer).addRun(unlockRunnable);
        try {
            helper.begin();

            helper.next();

            provider.getJwks(false);

            verify(delegate, only()).getJwks(false);
        } finally {
            helper.close();
        }
    }
}
