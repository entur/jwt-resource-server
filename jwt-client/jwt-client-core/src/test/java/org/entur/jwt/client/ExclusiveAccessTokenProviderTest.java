package org.entur.jwt.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ExclusiveAccessTokenProviderTest extends AbstractDelegateProviderTest {

    private ExclusiveAccessTokenProvider provider;

    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        provider = new ExclusiveAccessTokenProvider(fallback);
    }

    @Test
    public void shouldDelegateSequentialCallsAndFailuresUnchanged() throws Exception {
        AccessTokenRetryAfterException failure = new AccessTokenRetryAfterException("HTTP 429", null, 0);
        when(fallback.getAccessToken(false)).thenThrow(failure).thenReturn(accessToken);

        assertThat(assertThrows(AccessTokenRetryAfterException.class, () -> provider.getAccessToken(false))).isSameInstanceAs(failure);
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
        verify(fallback, times(2)).getAccessToken(false);
    }

    @Test
    public void shouldRejectConcurrentCallsWithoutReachingTheDelegate() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        when(fallback.getAccessToken(anyBoolean())).thenAnswer(invocation -> {
            started.countDown();
            assertThat(release.await(5, TimeUnit.SECONDS)).isTrue();
            return accessToken;
        });

        try (var executor = Executors.newSingleThreadExecutor()) {
            var first = executor.submit(() -> provider.getAccessToken(false));
            try {
                assertThat(started.await(5, TimeUnit.SECONDS)).isTrue();
                assertThat(assertThrows(AccessTokenUnavailableException.class, () -> provider.getAccessToken(true)))
                        .isNotInstanceOf(AccessTokenRetryAfterException.class);
                verify(fallback, times(1)).getAccessToken(anyBoolean());
            } finally {
                release.countDown();
            }
            assertThat(first.get(5, TimeUnit.SECONDS)).isSameInstanceAs(accessToken);
        }
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
    }

}
