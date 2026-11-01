package org.entur.jwt.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

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

    @ParameterizedTest
    @ValueSource(longs = {Long.MIN_VALUE, 0, Long.MAX_VALUE})
    public void shouldAlwaysRethrowRetryAfterUnchanged(long deadline) throws Exception {
        AccessTokenRetryAfterException failure = new AccessTokenRetryAfterException("HTTP 429", null, deadline);
        when(fallback.getAccessToken(false)).thenThrow(failure);

        assertThat(assertThrows(AccessTokenRetryAfterException.class, () -> provider.getAccessToken(false))).isSameInstanceAs(failure);
        verify(fallback, times(1)).getAccessToken(false);
    }

}
