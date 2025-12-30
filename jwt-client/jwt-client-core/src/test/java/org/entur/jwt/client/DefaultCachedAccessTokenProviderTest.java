package org.entur.jwt.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.Thread.State;
import java.util.concurrent.TimeUnit;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.only;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class DefaultCachedAccessTokenProviderTest extends AbstractDelegateProviderTest {

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

    private DefaultCachedAccessTokenProvider provider;

    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        provider = new DefaultCachedAccessTokenProvider(fallback, 10, TimeUnit.SECONDS, 15, TimeUnit.SECONDS);
    }

    @Test
    public void shouldUseFallbackWhenNotCached() throws Exception {
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
    }

    @Test
    public void shouldUseCachedValue() throws Exception {
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new AccessTokenException("TEST!"));
        provider.getAccessToken(false);
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
        verify(fallback, only()).getAccessToken(false);
    }

    @Test
    public void shouldUseFallbackWhenExpiredCache() throws Exception {
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenReturn(refreshedAccessToken);

        // first
        AccessToken first = provider.getAccessToken(false);
        assertThat(first).isSameInstanceAs(accessToken);
        verify(fallback, only()).getAccessToken(false);

        // second
        AccessToken second = provider.getAccessToken(provider.getExpires(1), false);
        assertThat(second).isSameInstanceAs(refreshedAccessToken);
        verify(fallback, times(2)).getAccessToken(false);
    }

    @Test
    public void shouldNotReturnExpiredValueWhenExpiredCache() throws Exception {
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new AccessTokenException("TEST!", null));
        AccessToken first = provider.getAccessToken(false);
        assertThat(first).isSameInstanceAs(accessToken);

        assertThrows(AccessTokenException.class, () -> {
            provider.getAccessToken(provider.getExpires(1), false);
        });
    }

    @Test
    public void shouldGetBaseProvider() throws Exception {
        assertThat(provider.getProvider()).isSameInstanceAs(fallback);
    }

    @Test
    public void shouldThrowExceptionIfAnotherThreadBlocksUpdateForTooLong() throws Exception {
        ThreadHelper helper = new ThreadHelper().addRun(lockRunnable).addPause().addRun(unlockRunnable);
        try {
            helper.start();
            while (helper.getState() != State.WAITING) {
                Thread.yield();
            }

            assertThrows(AccessTokenException.class, () -> {
                provider.getAccessToken(false);
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
                    provider.getAccessToken(false);
                } catch (Exception e) {
                    throw new RuntimeException();
                }
            }
        };

        when(fallback.getAccessToken(false)).thenReturn(accessToken);

        ThreadHelper helper = new ThreadHelper().addRun(lockRunnable).addPause().addRun(racer).addRun(unlockRunnable);
        try {
            helper.begin();

            helper.next();

            provider.getAccessToken(false);

            verify(fallback, only()).getAccessToken(false);
        } finally {
            helper.close();
        }
    }

}
