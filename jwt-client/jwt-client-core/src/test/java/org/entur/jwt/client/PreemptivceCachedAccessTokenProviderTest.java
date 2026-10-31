package org.entur.jwt.client;

import com.google.common.truth.Truth;
import org.entur.jwt.client.AbstractCachedAccessTokenProvider.AccessTokenCacheItem;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.only;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
        provider = new PreemptiveCachedAccessTokenProvider(fallback, 10, TimeUnit.SECONDS, 15, TimeUnit.SECONDS, 15, TimeUnit.SECONDS, 0, false);
    }
    
    @AfterEach
    public void shutdown() throws Exception {
        if(provider != null) {
            provider.close();
        }
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

        long justBeforeExpiry = provider.getExpires(-TimeUnit.SECONDS.toMillis(4));

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
        TestPreemptiveProvider timed = new TestPreemptiveProvider(fallback, 60_000, 60_000, false, directExecutor());
        provider = timed;
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new AccessTokenUnavailableException("TEST!")).thenReturn(refreshedAccessToken);

        // first
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
        verify(fallback, only()).getAccessToken(false);

        long justBeforeExpiry = provider.getExpires(-TimeUnit.SECONDS.toMillis(5));

        assertThat(provider.getAccessToken(justBeforeExpiry, false)).isSameInstanceAs(accessToken); // triggers a preemptive refresh attempt

        timed.advance(60, TimeUnit.SECONDS);

        assertThat(provider.getAccessToken(justBeforeExpiry, false)).isSameInstanceAs(accessToken); // triggers a another preemptive refresh attempt

        verify(fallback, times(3)).getAccessToken(false);

        // second
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(refreshedAccessToken); // should already be in cache
        verify(fallback, times(3)).getAccessToken(false);
    }

    @Test
    public void shouldFirePreemptivelyRefreshCacheAgainIfPreviousPreemptivelyRefreshAttemptFailedWithUncheckedException() throws Exception {
        TestPreemptiveProvider timed = new TestPreemptiveProvider(fallback, 60_000, 60_000, false, directExecutor());
        provider = timed;
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new IllegalStateException("TEST!")).thenReturn(refreshedAccessToken);

        assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
        verify(fallback, only()).getAccessToken(false);

        long justBeforeExpiry = provider.getExpires(-TimeUnit.SECONDS.toMillis(5));

        assertThat(provider.getAccessToken(justBeforeExpiry, false)).isSameInstanceAs(accessToken); // triggers a preemptive refresh attempt, which fails

        timed.advance(60, TimeUnit.SECONDS);

        assertThat(provider.getAccessToken(justBeforeExpiry, false)).isSameInstanceAs(accessToken); // triggers a another preemptive refresh attempt

        verify(fallback, times(3)).getAccessToken(false);

        assertThat(provider.getAccessToken(false)).isSameInstanceAs(refreshedAccessToken);
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

        provider = new PreemptiveCachedAccessTokenProvider(fallback, minimumTimeToLive, refreshTimeout, preemptiveRefresh, 0, true);

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
        Truth.assertThat(left).isAtLeast(limit - skew - 1);
        
        // sleep and check that keys were actually updated
        Thread.sleep(left + Math.min(25, 4 * skew));

        // note: added 100 ms to stabilize tests
        provider.getExecutorService().awaitTermination(100 + Math.min(25, 4 * skew), TimeUnit.MILLISECONDS);
        verify(fallback, times(2)).getAccessToken(false);

        // second access-token
        // and that no new call was necessary
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(refreshedAccessToken);
        verify(fallback, times(2)).getAccessToken(false);
    }
    
    @Test
    public void shouldRetryFailedEagerRefreshUntilItSucceedsWithoutRequests() throws Exception {
        TestPreemptiveProvider timed = newEagerProvider(directExecutor());
        provider = timed;
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new AccessTokenUnavailableException("Temporary outage")).thenThrow(new AccessTokenUnavailableException("Still unavailable")).thenReturn(refreshedAccessToken);

        provider.getAccessToken(false);
        for (int attempt = 0; attempt < 2; attempt++) {
            ScheduledFuture<?> previous = provider.getEagerScheduledFuture();
            ((Runnable) previous).run();

            ScheduledFuture<?> retry = provider.getEagerScheduledFuture();
            assertThat(retry).isNotSameInstanceAs(previous);
            assertThat(retry.isDone()).isFalse();
            assertThat(retry.getDelay(TimeUnit.MILLISECONDS)).isGreaterThan(0L);
            assertThat(retry.getDelay(TimeUnit.MILLISECONDS)).isAtMost(provider.getEagerErrorCooldown());
            timed.advance(60, TimeUnit.SECONDS);
        }

        ((Runnable) provider.getEagerScheduledFuture()).run();

        assertThat(provider.getCachedAccessToken()).isSameInstanceAs(refreshedAccessToken);
        assertThat(provider.getEagerScheduledFuture().isDone()).isFalse();
        verify(fallback, times(4)).getAccessToken(false);
    }

    @Test
    public void shouldRetryTrafficAfter15SecondsWhileEagerRetryWaitsOneMinute() throws Exception {
        TestPreemptiveProvider timed = newEagerProvider(directExecutor());
        provider = timed;
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new AccessTokenUnavailableException("Temporary outage")).thenReturn(refreshedAccessToken);

        provider.getAccessToken(false);
        ((Runnable) provider.getEagerScheduledFuture()).run();
        long refreshTime = provider.getRefreshable(1);
        timed.advance(14_999, TimeUnit.MILLISECONDS);
        provider.getAccessToken(refreshTime, false);

        assertThat(provider.getCachedAccessToken()).isSameInstanceAs(accessToken);
        verify(fallback, times(2)).getAccessToken(false);

        timed.advance(1, TimeUnit.MILLISECONDS);
        ((Runnable) provider.getEagerScheduledFuture()).run();
        assertThat(provider.getCachedAccessToken()).isSameInstanceAs(accessToken);
        verify(fallback, times(2)).getAccessToken(false);

        provider.getAccessToken(refreshTime, false);
        assertThat(provider.getCachedAccessToken()).isSameInstanceAs(refreshedAccessToken);
        verify(fallback, times(3)).getAccessToken(false);
    }

    @Test
    public void shouldAllowBlockingReloadDuringPreemptiveErrorCooldown() throws Exception {
        provider = newEagerProvider(directExecutor());
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new AccessTokenUnavailableException("Temporary outage")).thenReturn(refreshedAccessToken);

        provider.getAccessToken(false);
        ((Runnable) provider.getEagerScheduledFuture()).run();

        assertThat(provider.getAccessToken(provider.getExpires(1), false)).isSameInstanceAs(refreshedAccessToken);
        verify(fallback, times(3)).getAccessToken(false);
    }

    @ParameterizedTest
    @ValueSource(booleans = { false, true })
    public void shouldHonorConfiguredErrorCooldownFromFailureCompletion(boolean eager) throws Exception {
        TestPreemptiveProvider timed = new TestPreemptiveProvider(fallback, 90_000, 120_000, eager, directExecutor());
        provider = timed;
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenAnswer(invocation -> {
            timed.advance(10, TimeUnit.SECONDS);
            throw new AccessTokenUnavailableException("Slow failed refresh");
        }).thenReturn(refreshedAccessToken);

        provider.getAccessToken(false);
        long refreshTime = provider.getRefreshable(1);
        provider.getAccessToken(refreshTime, false);
        if (eager) {
            assertThat(provider.getEagerScheduledFuture().getDelay(TimeUnit.MILLISECONDS)).isGreaterThan(provider.getRefreshTimeout());
            assertThat(provider.getEagerScheduledFuture().getDelay(TimeUnit.MILLISECONDS)).isAtMost(120_000L);
        }

        provider.getAccessToken(refreshTime, false);
        timed.advance(89_999, TimeUnit.MILLISECONDS);
        provider.getAccessToken(refreshTime, false);
        verify(fallback, times(2)).getAccessToken(false);
        assertThat(provider.getCachedAccessToken()).isSameInstanceAs(accessToken);

        timed.advance(1, TimeUnit.MILLISECONDS);
        provider.getAccessToken(refreshTime, false);
        assertThat(provider.getCachedAccessToken()).isSameInstanceAs(refreshedAccessToken);
        verify(fallback, times(3)).getAccessToken(false);
    }

    @ParameterizedTest
    @CsvSource({ "15000,60000", "90000,20000" })
    public void shouldApplyEachCooldownIndependentlyFromFailureCompletion(long preemptiveCooldown, long eagerCooldown) throws Exception {
        TestPreemptiveProvider timed = new TestPreemptiveProvider(fallback, preemptiveCooldown, eagerCooldown, true, directExecutor());
        provider = timed;
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenAnswer(invocation -> {
            timed.advance(10, TimeUnit.SECONDS);
            throw new AccessTokenUnavailableException("Slow failed refresh");
        }).thenReturn(refreshedAccessToken);

        provider.getAccessToken(false);
        ((Runnable) provider.getEagerScheduledFuture()).run();
        long refreshTime = provider.getRefreshable(1);
        long firstCooldown = Math.min(preemptiveCooldown, eagerCooldown);
        timed.advance(firstCooldown / 2, TimeUnit.MILLISECONDS);

        provider.getAccessToken(refreshTime, false);
        ((Runnable) provider.getEagerScheduledFuture()).run();
        assertThat(provider.getCachedAccessToken()).isSameInstanceAs(accessToken);
        verify(fallback, times(2)).getAccessToken(false);

        timed.advance(firstCooldown - firstCooldown / 2, TimeUnit.MILLISECONDS);
        if (preemptiveCooldown < eagerCooldown) {
            ((Runnable) provider.getEagerScheduledFuture()).run();
            verify(fallback, times(2)).getAccessToken(false);
            provider.getAccessToken(refreshTime, false);
        } else {
            provider.getAccessToken(refreshTime, false);
            verify(fallback, times(2)).getAccessToken(false);
            ((Runnable) provider.getEagerScheduledFuture()).run();
        }

        assertThat(provider.getCachedAccessToken()).isSameInstanceAs(refreshedAccessToken);
        verify(fallback, times(3)).getAccessToken(false);
    }

    @Test
    public void shouldKeepEagerRetryScheduledIfTriggeredDuringErrorCooldown() throws Exception {
        TestPreemptiveProvider timed = newEagerProvider(directExecutor());
        provider = timed;
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new AccessTokenUnavailableException("Temporary outage")).thenReturn(refreshedAccessToken);

        provider.getAccessToken(false);
        ((Runnable) provider.getEagerScheduledFuture()).run();
        ScheduledFuture<?> early = provider.getEagerScheduledFuture();
        ((Runnable) early).run();

        verify(fallback, times(2)).getAccessToken(false);
        assertThat(provider.getEagerScheduledFuture()).isNotSameInstanceAs(early);
        assertThat(provider.getEagerScheduledFuture().isDone()).isFalse();
        timed.advance(59, TimeUnit.SECONDS);
        ((Runnable) provider.getEagerScheduledFuture()).run();
        verify(fallback, times(2)).getAccessToken(false);
        timed.advance(1, TimeUnit.SECONDS);
        ((Runnable) provider.getEagerScheduledFuture()).run();
        assertThat(provider.getCachedAccessToken()).isSameInstanceAs(refreshedAccessToken);
    }

    @Test
    public void shouldRejectNegativePreemptiveErrorCooldown() {
        assertThrows(IllegalArgumentException.class, () -> new PreemptiveCachedAccessTokenProvider(fallback, 1000, 1000, 2000, -1, 60_000, 25, true));
    }

    @Test
    public void shouldRejectNegativeEagerErrorCooldown() {
        assertThrows(IllegalArgumentException.class, () -> new PreemptiveCachedAccessTokenProvider(fallback, 1000, 1000, 2000, 15_000, -1, 25, true));
    }

    @Test
    public void shouldAllowImmediateTrafficTriggeredRetryWhenErrorCooldownIsZero() throws Exception {
        provider = new TestPreemptiveProvider(fallback, 0, 60_000, true, directExecutor());
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new AccessTokenUnavailableException("Temporary outage")).thenReturn(refreshedAccessToken);

        provider.getAccessToken(false);
        long refreshTime = provider.getRefreshable(1);
        provider.getAccessToken(refreshTime, false);
        provider.getAccessToken(refreshTime, false);

        assertThat(provider.getCachedAccessToken()).isSameInstanceAs(refreshedAccessToken);
        verify(fallback, times(3)).getAccessToken(false);
    }

    @Test
    public void shouldKeepEagerRetriesIndependentWhenEagerErrorCooldownIsZero() throws Exception {
        provider = new TestPreemptiveProvider(fallback, 90_000, 0, true, directExecutor());
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new AccessTokenUnavailableException("Temporary outage")).thenReturn(refreshedAccessToken);

        provider.getAccessToken(false);
        ((Runnable) provider.getEagerScheduledFuture()).run();
        ScheduledFuture<?> retry = provider.getEagerScheduledFuture();
        assertThat(retry.getDelay(TimeUnit.MILLISECONDS)).isGreaterThan(0L);
        assertThat(retry.getDelay(TimeUnit.MILLISECONDS)).isAtMost(1000L);

        ((Runnable) retry).run();

        assertThat(provider.getCachedAccessToken()).isSameInstanceAs(refreshedAccessToken);
        verify(fallback, times(3)).getAccessToken(false);
    }

    @ParameterizedTest
    @ValueSource(longs = { 0, -60_000 })
    public void shouldContinueEagerRefreshBeforeDeadlineWhenReplacementDoesNotExtendExpiry(long expiryChange) throws Exception {
        provider = newEagerProvider(directExecutor());
        AccessToken replacement = new AccessToken("replacement", "bearer", accessToken.getExpires() + expiryChange);
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenReturn(replacement).thenReturn(refreshedAccessToken);

        provider.getAccessToken(false);
        for (AccessToken expected : List.of(replacement, refreshedAccessToken)) {
            ScheduledFuture<?> scheduled = provider.getEagerScheduledFuture();
            ((Runnable) scheduled).run();

            assertThat(provider.getCachedAccessToken()).isSameInstanceAs(expected);
            assertThat(provider.getEagerScheduledFuture()).isNotSameInstanceAs(scheduled);
            assertThat(provider.getEagerScheduledFuture().isDone()).isFalse();
        }
        verify(fallback, times(3)).getAccessToken(false);
    }

    @ParameterizedTest
    @ValueSource(longs = { 0, -60_000 })
    public void shouldStopEagerRefreshWhenValidReplacementHasNoFutureRefreshDeadline(long expiryChange) throws Exception {
        provider = newEagerProvider(directExecutor());
        AccessToken replacement = new AccessToken("replacement", "bearer", accessToken.getExpires() + expiryChange);
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenReturn(replacement);

        provider.getAccessToken(false);
        AccessTokenCacheItem current = provider.getCache();
        ScheduledFuture<?> scheduled = provider.getEagerScheduledFuture();
        long deadline = current.getRefreshable() - provider.getRefreshTimeout();

        // Simulate the timer at its deadline rather than running it early.
        provider.preemptiveRefresh(deadline, current, true);

        assertThat(provider.getCachedAccessToken(deadline)).isSameInstanceAs(replacement);
        assertThat(provider.getEagerScheduledFuture()).isSameInstanceAs(scheduled);
        assertThat(scheduled.isCancelled()).isTrue();
        verify(fallback, times(2)).getAccessToken(false);
    }

    @Test
    public void shouldIgnoreStaleAndDuplicatePreemptiveRefreshRequests() throws Exception {
        List<Runnable> updates = new ArrayList<>();
        ExecutorService executor = mock(ExecutorService.class);
        doAnswer(invocation -> {
            updates.add(invocation.getArgument(0, Runnable.class));
            return null;
        }).when(executor).execute(any(Runnable.class));
        provider = newEagerProvider(executor);
        AccessToken next = new AccessToken("next", "bearer", refreshedAccessToken.getExpires() + 60_000);
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenReturn(refreshedAccessToken).thenReturn(next);

        provider.getAccessToken(false);
        AccessTokenCacheItem previous = provider.getCache();
        ((Runnable) provider.getEagerScheduledFuture()).run();
        updates.getFirst().run();
        AccessTokenCacheItem current = provider.getCache();

        ((Runnable) provider.getEagerScheduledFuture()).run();
        provider.preemptiveRefresh(System.currentTimeMillis(), previous, true);
        provider.preemptiveRefresh(System.currentTimeMillis(), current, true);

        assertThat(updates).hasSize(2);
        updates.get(1).run();
        assertThat(provider.getCachedAccessToken()).isSameInstanceAs(next);
        assertThat(provider.getEagerScheduledFuture().isDone()).isFalse();
    }

    @Test
    public void shouldCancelScheduledEagerRetryOnClose() throws Exception {
        provider = newEagerProvider(directExecutor());
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new AccessTokenUnavailableException("Temporary outage"));

        provider.getAccessToken(false);
        ScheduledFuture<?> first = provider.getEagerScheduledFuture();
        ((Runnable) first).run();
        ScheduledFuture<?> retry = provider.getEagerScheduledFuture();
        assertThat(retry).isNotSameInstanceAs(first);

        provider.close();
        assertThat(retry.isCancelled()).isTrue();
        ((Runnable) retry).run();
        verify(fallback, times(2)).getAccessToken(false);
    }

    @Test
    public void shouldRetryEagerRefreshWhenReplacementTokenIsAlreadyExpired() throws Exception {
        TestPreemptiveProvider timed = newEagerProvider(directExecutor());
        provider = timed;
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenReturn(new AccessToken("expired", "bearer", accessToken.getExpires() - TimeUnit.HOURS.toMillis(1))).thenReturn(refreshedAccessToken);

        provider.getAccessToken(false);
        ScheduledFuture<?> first = provider.getEagerScheduledFuture();
        ((Runnable) first).run();
        ScheduledFuture<?> retry = provider.getEagerScheduledFuture();
        assertThat(retry).isNotSameInstanceAs(first);
        assertThat(retry.isDone()).isFalse();
        timed.advance(60, TimeUnit.SECONDS);
        ((Runnable) retry).run();

        assertThat(provider.getCachedAccessToken()).isSameInstanceAs(refreshedAccessToken);
    }

    @Test
    public void shouldKeepEagerRetryAfterForegroundRefreshReturnsExpiredReplacement() throws Exception {
        TestPreemptiveProvider timed = newEagerProvider(directExecutor());
        provider = timed;
        AccessToken expired = new AccessToken("expired", "bearer", accessToken.getExpires() - TimeUnit.HOURS.toMillis(1));
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new AccessTokenUnavailableException("Temporary outage")).thenReturn(expired).thenReturn(refreshedAccessToken);

        provider.getAccessToken(false);
        ((Runnable) provider.getEagerScheduledFuture()).run();
        ScheduledFuture<?> previousRetry = provider.getEagerScheduledFuture();

        assertThrows(AccessTokenUnavailableException.class, () -> provider.getAccessToken(true));

        ScheduledFuture<?> retry = provider.getEagerScheduledFuture();
        assertThat(previousRetry.isCancelled()).isTrue();
        assertThat(retry).isNotSameInstanceAs(previousRetry);
        assertThat(retry.isDone()).isFalse();
        assertThat(retry.getDelay(TimeUnit.MILLISECONDS)).isGreaterThan(0L);
        assertThat(retry.getDelay(TimeUnit.MILLISECONDS)).isAtMost(provider.getEagerErrorCooldown());

        timed.advance(60, TimeUnit.SECONDS);
        ((Runnable) retry).run();

        assertThat(provider.getCachedAccessToken()).isSameInstanceAs(refreshedAccessToken);
        assertThat(provider.getEagerScheduledFuture().isDone()).isFalse();
        verify(fallback, times(4)).getAccessToken(false);
    }

    @Test
    public void shouldNotRescheduleFailedInFlightEagerRefreshAfterClose() throws Exception {
        ExecutorService executor = mock(ExecutorService.class);
        provider = newEagerProvider(executor);
        when(fallback.getAccessToken(false)).thenReturn(accessToken).thenThrow(new AccessTokenUnavailableException("Temporary outage"));

        provider.getAccessToken(false);
        ScheduledFuture<?> scheduled = provider.getEagerScheduledFuture();
        ((Runnable) scheduled).run();
        ArgumentCaptor<Runnable> update = ArgumentCaptor.forClass(Runnable.class);
        verify(executor).execute(update.capture());

        provider.close();
        update.getValue().run();

        assertThat(provider.getEagerScheduledFuture()).isSameInstanceAs(scheduled);
        assertThat(scheduled.isDone()).isTrue();
        verify(fallback, times(2)).getAccessToken(false);
    }

    private TestPreemptiveProvider newEagerProvider(ExecutorService executor) {
        return new TestPreemptiveProvider(fallback, executor);
    }

    private static class TestPreemptiveProvider extends PreemptiveCachedAccessTokenProvider {

        private long nowNanos;

        TestPreemptiveProvider(AccessTokenProvider fallback, ExecutorService executor) {
            super(fallback, 1000, 60_000, 30_000, 25, true, executor, false);
        }

        TestPreemptiveProvider(AccessTokenProvider fallback, long preemptiveCooldown, long eagerCooldown, boolean eager, ExecutorService executor) {
            super(fallback, 1000, 60_000, 30_000, preemptiveCooldown, eagerCooldown, 25, eager, executor, false);
        }

        @Override
        protected long nanoTime() {
            return nowNanos;
        }

        void advance(long duration, TimeUnit unit) {
            nowNanos += unit.toNanos(duration);
        }
    }

    private ExecutorService directExecutor() {
        ExecutorService executor = mock(ExecutorService.class);
        doAnswer(invocation -> {
            invocation.getArgument(0, Runnable.class).run();
            return null;
        }).when(executor).execute(any(Runnable.class));
        return executor;
    }

    @Test
    public void shouldConstrainPreemptivelyRefreshCache() throws Exception {
        long minimumTimeToLive = 1000; 
        long refreshTimeout = 150;
        long preemptiveRefresh = 8000; // refresh after just 2000 ms
        
        long validFor = 10000;
        
        long now = System.currentTimeMillis();

        int percent = 50; // should limit refresh to 5000ms
        
        fallback = mock(AccessTokenProvider.class);
        accessToken = new AccessToken("a.b.c", "bearer", now + validFor);
        provider = new PreemptiveCachedAccessTokenProvider(fallback, minimumTimeToLive, refreshTimeout, preemptiveRefresh, percent, true);
        when(fallback.getAccessToken(false)).thenReturn(accessToken);

        // first access-token
        assertThat(provider.getAccessToken(false)).isSameInstanceAs(accessToken);
        verify(fallback, only()).getAccessToken(false);

        long skew = System.currentTimeMillis() - now;
        long constraintsInMillis = (validFor * percent) / 100;
        long refreshable = provider.getRefreshable(-now);

        Truth.assertThat(refreshable).isAtMost(constraintsInMillis + skew);
        Truth.assertThat(refreshable).isAtLeast(constraintsInMillis - skew);
    }    
    
}
