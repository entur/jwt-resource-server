package org.entur.jwt.client;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RetryAfterAccessTokenProviderTest {

    @Test
    void shouldPreserveDeadlineAcrossRejectedCallsAndRecoverAtItsBoundary() throws Exception {
        TestProvider provider = new TestProvider();
        provider.headerFailure = true;
        provider.header = "120";
        AccessTokenRetryAfterException failure = assertThrows(AccessTokenRetryAfterException.class,
                () -> provider.getAccessToken(false));
        long deadline = failure.getRetryAfterDeadlineNanos();
        assertThat(deadline - provider.nowNanos).isEqualTo(TimeUnit.SECONDS.toNanos(120));

        provider.headerFailure = false;
        for (int seconds : new int[]{30, 60, 29}) {
            provider.advance(seconds, TimeUnit.SECONDS);
            AccessTokenRetryAfterException rejected = assertThrows(AccessTokenRetryAfterException.class,
                    () -> provider.getAccessToken(true));
            assertThat(rejected.getRetryAfterDeadlineNanos()).isEqualTo(deadline);
            assertThat(provider.calls).isEqualTo(1);
        }
        provider.advance(1, TimeUnit.SECONDS);
        assertThat(provider.getAccessToken(false).getValue()).isEqualTo("token");
        assertThat(provider.getAccessToken(true).getValue()).isEqualTo("token");
        assertThat(provider.calls).isEqualTo(3);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"invalid", "-1", "1.5"})
    void shouldUseFifteenSecondFallbackForMissingOrMalformedHeaders(String header) throws Exception {
        TestProvider provider = new TestProvider();
        provider.headerFailure = true;
        provider.header = header;
        AccessTokenRetryAfterException failure = assertThrows(AccessTokenRetryAfterException.class,
                () -> provider.getAccessToken(false));
        assertThat(failure.getRetryAfterDeadlineNanos() - provider.nowNanos).isEqualTo(TimeUnit.SECONDS.toNanos(15));
        provider.headerFailure = false;
        provider.advance(14_999, TimeUnit.MILLISECONDS);
        assertThrows(AccessTokenRetryAfterException.class, () -> provider.getAccessToken(false));
        provider.advance(1, TimeUnit.MILLISECONDS);
        assertThat(provider.getAccessToken(false).getValue()).isEqualTo("token");
        assertThat(provider.calls).isEqualTo(2);
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "2", " 2 "})
    void shouldHonorValidHeadersShorterThanTheFallback(String header) throws Exception {
        TestProvider provider = new TestProvider();
        provider.headerFailure = true;
        provider.header = header;
        assertThrows(AccessTokenRetryAfterException.class, () -> provider.getAccessToken(false));
        provider.headerFailure = false;
        provider.advance(Long.parseLong(header.trim()), TimeUnit.SECONDS);
        assertThat(provider.getAccessToken(false).getValue()).isEqualTo("token");
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "Sat, 31 Oct 2026 11:59:00 GMT"})
    void shouldDeferZeroDelayFailuresToTheNextCallWithoutAddingAWait(String header) throws Exception {
        TestProvider http = new TestProvider();
        http.setRetryAfterFallbackMillis(0);
        http.headerFailure = true;
        http.header = header;
        RetryingAccessTokenProvider provider = new RetryingAccessTokenProvider(http);

        AccessTokenRetryAfterException failure = assertThrows(AccessTokenRetryAfterException.class,
                () -> provider.getAccessToken(false));
        assertThat(failure.getRetryAfterDeadlineNanos()).isEqualTo(http.nowNanos);
        assertThat(http.calls).isEqualTo(1);

        http.headerFailure = false;
        assertThat(provider.getAccessToken(false).getValue()).isEqualTo("token");
        assertThat(http.calls).isEqualTo(2);
    }

    @Test
    void shouldLeaveFailuresWithoutAUsableHeaderOrdinaryWhenTheFallbackIsZero() throws Exception {
        TestProvider http = new TestProvider();
        http.setRetryAfterFallbackMillis(0);
        http.headerFailure = true;
        RetryingAccessTokenProvider provider = new RetryingAccessTokenProvider(http);

        assertThat(assertThrows(AccessTokenUnavailableException.class, () -> provider.getAccessToken(false)))
                .isNotInstanceOf(AccessTokenRetryAfterException.class);
        assertThat(http.calls).isEqualTo(2);
        assertThat(http.getRetryAfterDeadlineNanos()).isNull();

        http.headerFailure = false;
        http.failure = new AccessTokenUnavailableException("down");
        assertThat(assertThrows(AccessTokenUnavailableException.class, () -> http.getAccessToken(false)))
                .isNotInstanceOf(AccessTokenRetryAfterException.class);
        assertThat(http.getRetryAfterDeadlineNanos()).isNull();

        http.headerFailure = true;
        http.header = "120";
        AccessTokenRetryAfterException failure = assertThrows(AccessTokenRetryAfterException.class,
                () -> provider.getAccessToken(false));
        assertThat(failure.getRetryAfterDeadlineNanos() - http.nowNanos).isEqualTo(TimeUnit.SECONDS.toNanos(120));
    }

    @Test
    void shouldConvertHttpDateOnceAndIgnoreLaterWallClockChanges() throws Exception {
        TestProvider provider = new TestProvider();
        provider.headerFailure = true;
        provider.header = "Sat, 31 Oct 2026 12:02:00 GMT";
        AccessTokenRetryAfterException failure = assertThrows(AccessTokenRetryAfterException.class,
                () -> provider.getAccessToken(false));
        assertThat(failure.getRetryAfterDeadlineNanos() - provider.nowNanos).isEqualTo(TimeUnit.MINUTES.toNanos(2));
        provider.headerFailure = false;
        provider.nowMillis += TimeUnit.DAYS.toMillis(30);
        assertThrows(AccessTokenRetryAfterException.class, () -> provider.getAccessToken(false));
        provider.nowNanos += TimeUnit.MINUTES.toNanos(2);
        assertThat(provider.getAccessToken(false).getValue()).isEqualTo("token");
    }

    @Test
    void shouldTreatAPastHttpDateAsAnExpiredDeadline() throws Exception {
        TestProvider provider = new TestProvider();
        provider.headerFailure = true;
        provider.header = "Sat, 31 Oct 2026 11:59:00 GMT";
        assertThrows(AccessTokenRetryAfterException.class, () -> provider.getAccessToken(false));
        provider.headerFailure = false;
        assertThat(provider.getAccessToken(false).getValue()).isEqualTo("token");
    }

    @Test
    void shouldMeasureFallbackFromFailureCompletionAndPreserveItsCause() throws Exception {
        TestProvider provider = new TestProvider();
        provider.failure = new AccessTokenUnavailableException("connection failed");
        provider.requestDurationMillis = 10_000;
        AccessTokenRetryAfterException failure = assertThrows(AccessTokenRetryAfterException.class,
                () -> provider.getAccessToken(false));
        assertThat(failure.getCause()).isSameInstanceAs(provider.failure);
        assertThat(failure.getRetryAfterDeadlineNanos() - provider.nowNanos).isEqualTo(TimeUnit.SECONDS.toNanos(15));
    }

    @Test
    void shouldBackOffOtherTokenFailuresWithoutChangingTheirExceptionType() throws Exception {
        TestProvider provider = new TestProvider();
        provider.failure = new AccessTokenException("invalid credentials");
        assertThat(assertThrows(AccessTokenException.class, () -> provider.getAccessToken(false)))
                .isSameInstanceAs(provider.failure);
        assertThrows(AccessTokenRetryAfterException.class, () -> provider.getAccessToken(false));
        assertThat(provider.calls).isEqualTo(1);
    }

    @Test
    void shouldKeepTheLongestDeadlineAndHandleNanoTimeWraparound() throws Exception {
        TestProvider provider = new TestProvider();
        provider.nowNanos = Long.MAX_VALUE - TimeUnit.SECONDS.toNanos(1);
        provider.retryAfterException("long response", "120");
        provider.retryAfterException("short response", "10");
        assertThat(provider.getRetryAfterDeadlineNanos() - provider.nowNanos).isEqualTo(TimeUnit.SECONDS.toNanos(120));
        assertThrows(AccessTokenRetryAfterException.class, () -> provider.getAccessToken(false));
        provider.advance(120, TimeUnit.SECONDS);
        assertThat(provider.getAccessToken(false).getValue()).isEqualTo("token");
    }

    @ParameterizedTest
    @ValueSource(strings = {"9223372036854775807", "999999999999999999999999"})
    void shouldSaturateVeryLongServerDelaysWithoutBecomingImmediatelyRetryable(String header) throws Exception {
        TestProvider provider = new TestProvider();
        provider.retryAfterException("long response", header);
        assertThat(provider.getRetryAfterDeadlineNanos() - provider.nowNanos).isEqualTo(Long.MAX_VALUE);
        assertThrows(AccessTokenRetryAfterException.class, () -> provider.getAccessToken(false));
        assertThat(provider.calls).isEqualTo(0);
    }

    @Test
    void shouldSupportConfiguredFallback() throws Exception {
        TestProvider provider = new TestProvider();
        provider.setRetryAfterFallbackMillis(30_000);
        provider.headerFailure = true;
        AccessTokenRetryAfterException failure = assertThrows(AccessTokenRetryAfterException.class,
                () -> provider.getAccessToken(false));
        assertThat(failure.getRetryAfterDeadlineNanos() - provider.nowNanos).isEqualTo(TimeUnit.SECONDS.toNanos(30));
        assertThrows(IllegalArgumentException.class, () -> provider.setRetryAfterFallbackMillis(-1));
    }

    @Test
    void shouldNotFanOutConcurrentUncachedRequestsOrBackOffAfterSuccess() throws Exception {
        TestProvider http = new TestProvider();
        http.started = new CountDownLatch(1);
        http.release = new CountDownLatch(1);
        AccessTokenProvider provider = new AccessTokenProviderBuilder(http).cached(false).retrying(false).health(false).build();
        try (var executor = Executors.newSingleThreadExecutor()) {
            var first = executor.submit(() -> provider.getAccessToken(false));
            try {
                assertThat(http.started.await(5, TimeUnit.SECONDS)).isTrue();
                assertThrows(AccessTokenUnavailableException.class, () -> provider.getAccessToken(false));
                assertThat(http.calls).isEqualTo(1);
            } finally {
                http.release.countDown();
            }
            assertThat(first.get(5, TimeUnit.SECONDS).getValue()).isEqualTo("token");
        }
        assertThat(provider.getAccessToken(false).getValue()).isEqualTo("token");
        assertThat(http.getRetryAfterDeadlineNanos()).isNull();
    }

    @Test
    void shouldConfigureHttpBackoffWithoutCachingThroughTheBuilder() throws Exception {
        TestProvider http = new TestProvider();
        http.headerFailure = true;
        AccessTokenProvider provider = new AccessTokenProviderBuilder(http).cached(false).retrying(false).health(false)
                .retryAfter(1, TimeUnit.MINUTES).build();
        AccessTokenRetryAfterException failure = assertThrows(AccessTokenRetryAfterException.class,
                () -> provider.getAccessToken(false));
        assertThat(failure.getRetryAfterDeadlineNanos() - http.nowNanos).isEqualTo(TimeUnit.MINUTES.toNanos(1));

        TestProvider ordinary = new TestProvider();
        ordinary.headerFailure = true;
        AccessTokenProvider withoutFallback = new AccessTokenProviderBuilder(ordinary).cached(false).retrying(false).health(false)
                .retryAfter(0, TimeUnit.SECONDS).build();
        assertThat(assertThrows(AccessTokenUnavailableException.class, () -> withoutFallback.getAccessToken(false)))
                .isNotInstanceOf(AccessTokenRetryAfterException.class);
    }

    @Test
    void shouldServeCachedTokensButRejectForcedAndExpiredLoadsDuringBackoff() throws Exception {
        TestProvider http = new TestProvider();
        try (DefaultCachedAccessTokenProvider cache = new DefaultCachedAccessTokenProvider(http, 1000, 1000)) {
            AccessToken token = cache.getAccessToken(http.nowMillis, false);
            http.headerFailure = true;
            http.header = "1200";
            AccessTokenRetryAfterException failure = assertThrows(AccessTokenRetryAfterException.class,
                    () -> cache.getAccessToken(http.nowMillis, true));
            long deadline = failure.getRetryAfterDeadlineNanos();
            assertThat(cache.getAccessToken(http.nowMillis, false)).isSameInstanceAs(token);
            assertThrows(AccessTokenRetryAfterException.class, () -> cache.getAccessToken(http.nowMillis, true));
            http.advance(600, TimeUnit.SECONDS);
            assertThat(cache.getCachedAccessToken(http.nowMillis)).isNull();
            assertThrows(AccessTokenRetryAfterException.class, () -> cache.getAccessToken(http.nowMillis, false));
            assertThat(http.getRetryAfterDeadlineNanos()).isEqualTo(deadline);
            assertThat(http.calls).isEqualTo(2);
            http.advance(600, TimeUnit.SECONDS);
            http.headerFailure = false;
            assertThat(cache.getAccessToken(http.nowMillis, false)).isNotSameInstanceAs(token);
            assertThat(http.calls).isEqualTo(3);
        }
    }

    @Test
    void shouldKeepBackoffLocalToOneProviderInstance() throws Exception {
        TestProvider first = new TestProvider();
        first.headerFailure = true;
        first.header = "120";
        assertThrows(AccessTokenRetryAfterException.class, () -> first.getAccessToken(false));
        TestProvider second = new TestProvider();
        assertThat(second.getAccessToken(false).getValue()).isEqualTo("token");
        assertThrows(AccessTokenRetryAfterException.class, () -> first.getAccessToken(false));
        assertThat(first.calls).isEqualTo(1);
        assertThat(second.calls).isEqualTo(1);
    }

    @Test
    void shouldKeepRefreshingHealthChecksFromBypassingDefaultBackoff() throws Exception {
        TestProvider http = new TestProvider();
        http.failure = new AccessTokenUnavailableException("connection failed");
        try (AccessTokenProvider provider = new AccessTokenProviderBuilder(http).cached(false).retrying(false).health(true).build()) {
            assertThat(provider.getHealth(true).isSuccess()).isFalse();
            long deadline = http.getRetryAfterDeadlineNanos();
            assertThat(deadline - http.nowNanos).isEqualTo(TimeUnit.SECONDS.toNanos(15));
            http.failure = null;
            assertThat(provider.getHealth(true).isSuccess()).isFalse();
            http.advance(14, TimeUnit.SECONDS);
            assertThat(provider.getHealth(true).isSuccess()).isFalse();
            assertThat(http.getRetryAfterDeadlineNanos()).isEqualTo(deadline);
            assertThat(http.calls).isEqualTo(1);
            http.advance(1, TimeUnit.SECONDS);
            assertThat(provider.getHealth(true).isSuccess()).isTrue();
            assertThat(http.calls).isEqualTo(2);
        }
    }

    @Test
    void shouldPreventAnotherGrantBeforeTheRefreshTokenIsPublished() throws Exception {
        TestStatefulProvider http = new TestStatefulProvider();
        AccessTokenProvider provider = new AccessTokenProviderBuilder(http).cached(false).retrying(false).health(false).build();
        try (var executor = Executors.newSingleThreadExecutor()) {
            var first = executor.submit(() -> provider.getAccessToken(false));
            try {
                assertThat(http.beforePublication.await(5, TimeUnit.SECONDS)).isTrue();
                assertThrows(AccessTokenUnavailableException.class, () -> provider.getAccessToken(false));
                assertThat(http.issueCalls).isEqualTo(1);
            } finally {
                http.publish.countDown();
            }
            assertThat(first.get(5, TimeUnit.SECONDS).getValue()).isEqualTo("token");
        }
        assertThat(http.getRefreshToken().getValue()).isEqualTo("session");
        provider.getAccessToken(false);
        assertThat(http.issueCalls).isEqualTo(1);
        assertThat(http.refreshCalls).isEqualTo(1);
    }

    private static class TestStatefulProvider extends AbstractStatefulUrlAccessTokenProvider {

        private static final ClientCredentialsResponse RESPONSE = JsonMapper.builder().build().readValue(
                "{\"access_token\":\"token\",\"token_type\":\"Bearer\",\"expires_in\":600,\"refresh_token\":\"session\"}",
                ClientCredentialsResponse.class);

        private final CountDownLatch beforePublication = new CountDownLatch(1);
        private final CountDownLatch publish = new CountDownLatch(1);
        private int issueCalls;
        private int refreshCalls;

        private TestStatefulProvider() throws Exception {
            super(URI.create("https://issuer.example/token").toURL(), Map.of(), Map.of(), null, null);
        }

        @Override
        protected <T> T requestToken(TokenRequest<T> request) throws AccessTokenException {
            T result = super.requestToken(request);
            if (result instanceof ClientCredentialsResponse) {
                beforePublication.countDown();
                try {
                    assertThat(publish.await(5, TimeUnit.SECONDS)).isTrue();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new AccessTokenUnavailableException(e);
                }
            }
            return result;
        }

        @Override
        protected ClientCredentialsResponse getToken() {
            issueCalls++;
            return RESPONSE;
        }

        @Override
        protected ClientCredentialsResponse getToken(RefreshToken token) {
            assertThat(token.getValue()).isEqualTo("session");
            refreshCalls++;
            return RESPONSE;
        }

        @Override
        protected void close(long time) {
        }
    }

    private static class TestProvider extends AbstractUrlAccessTokenProvider {

        private static final ClientCredentialsResponse RESPONSE = JsonMapper.builder().build().readValue(
                "{\"access_token\":\"token\",\"token_type\":\"Bearer\",\"expires_in\":600}", ClientCredentialsResponse.class);

        private long nowNanos = 1_000_000;
        private long nowMillis = Instant.parse("2026-10-31T12:00:00Z").toEpochMilli();
        private int calls;
        private boolean headerFailure;
        private String header;
        private AccessTokenException failure;
        private long requestDurationMillis;
        private CountDownLatch started;
        private CountDownLatch release;

        private TestProvider() throws Exception {
            super(URI.create("https://issuer.example/token").toURL(), Map.of(), Map.of());
        }

        @Override
        protected ClientCredentialsResponse getToken() throws AccessTokenException {
            calls++;
            if (started != null) {
                started.countDown();
                try {
                    assertThat(release.await(5, TimeUnit.SECONDS)).isTrue();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new AccessTokenUnavailableException(e);
                }
            }
            advance(requestDurationMillis, TimeUnit.MILLISECONDS);
            if (headerFailure) {
                throw retryAfterException("HTTP 503", header);
            }
            if (failure != null) {
                throw failure;
            }
            return RESPONSE;
        }

        private void advance(long value, TimeUnit unit) {
            nowNanos += unit.toNanos(value);
            nowMillis += unit.toMillis(value);
        }

        @Override
        protected long nanoTime() {
            return nowNanos;
        }

        @Override
        protected long currentTimeMillis() {
            return nowMillis;
        }

        @Override
        public boolean supportsHealth() {
            return false;
        }
    }
}
