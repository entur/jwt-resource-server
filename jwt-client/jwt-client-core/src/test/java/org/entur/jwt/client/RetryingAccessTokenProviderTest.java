package org.entur.jwt.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class RetryingAccessTokenProviderTest extends AbstractDelegateProviderTest {

    private RetryingAccessTokenProvider provider;

    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        provider = new RetryingAccessTokenProvider(fallback);
    }

    @Test
    public void shouldReturnListOnSuccess() throws Exception {
        when(fallback.getAccessToken(false)).thenReturn(accessToken);
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
        verify(fallback, times(1)).getAccessToken(false);
    }

    @Test
    public void shouldRetryWhenUnavailable() throws Exception {
        when(fallback.getAccessToken(false)).thenThrow(new AccessTokenUnavailableException("TEST!", null)).thenReturn(accessToken);
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
        verify(fallback, times(2)).getAccessToken(false);
    }

    @Test
    public void shouldNotRetryMoreThanOnce() throws Exception {
        when(fallback.getAccessToken(false)).thenThrow(new AccessTokenUnavailableException("TEST!", null));

        assertThrows(AccessTokenUnavailableException.class, () -> {
            try {
                provider.getAccessToken(false);
            } finally {
                verify(fallback, times(2)).getAccessToken(false);
            }
        });
    }

    @Test
    public void shouldGetBaseProvider() throws Exception {
        assertThat(provider.getProvider()).isSameInstanceAs(fallback);
    }

    @Test
    public void shouldNotRetryOrReplaceAnActiveRetryAfterFailure() throws Exception {
        provider = new RetryingAccessTokenProvider(fallback) {
            @Override
            protected long nanoTime() {
                return 100;
            }
        };
        AccessTokenRetryAfterException failure = new AccessTokenRetryAfterException("HTTP 429", null, TimeUnit.SECONDS.toNanos(120), true);
        when(fallback.getAccessToken(false)).thenThrow(failure);

        assertThat(assertThrows(AccessTokenRetryAfterException.class, () -> provider.getAccessToken(false))).isSameInstanceAs(failure);
        verify(fallback, times(1)).getAccessToken(false);
    }

    @Test
    public void shouldRetryWhenTheRetryAfterDeadlineHasElapsed() throws Exception {
        provider = new RetryingAccessTokenProvider(fallback) {
            @Override
            protected long nanoTime() {
                return 100;
            }
        };
        when(fallback.getAccessToken(false))
                .thenThrow(new AccessTokenRetryAfterException("HTTP 503", null, 100, true)).thenReturn(accessToken);
        when(fallback.getRetryAfterDeadlineNanos()).thenReturn(100L);
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
        verify(fallback, times(2)).getAccessToken(false);
    }
}
