package org.entur.jwt.spring.decode.cache;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSetCacheRefreshEvaluator;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.OutageTolerantJWKSetSource;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource;
import com.nimbusds.jose.jwk.source.RetryingJWKSetSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.events.EventListener;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests the listener with a real decoder, and real events fired by real JWK sources.
 */
class DecodedJwtCacheJwkEventListenerTest {

    private static final long OUTAGE_CACHE_TIME_TO_LIVE = 1000;

    private final DecodedJwtCacheJwtDecoder decoder = new DecodedJwtCacheJwtDecoder(token -> {
        throw new IllegalStateException("Not used");
    }, jwt -> OAuth2TokenValidatorResult.success(), 0, 10);

    private final DecodedJwtCacheJwkEventListener listener = new DecodedJwtCacheJwkEventListener(decoder);

    private final JWKSet jwkSet = new JWKSet(new OctetSequenceKey.Builder("secret-material".getBytes()).keyID("kid1").build());

    private final TestJWKSetSource source = new TestJWKSetSource(jwkSet);

    private static final long JWK_CACHE_TIME_TO_LIVE = 60_000;

    // caching -> outage tolerant -> retrying -> source, i.e. the order used by JWKSourceBuilder.
    private final CachingJWKSetSource<SecurityContext> chain = chain(source, 1000);

    // the JWK set as returned by the chain on the previous call, so that the next call can force a refresh
    private JWKSet previous;

    private final ListAppender<ILoggingEvent> logAppender = new ListAppender<>();

    private CachingJWKSetSource<SecurityContext> chain(JWKSetSource<SecurityContext> source, long refreshTimeout) {
        return chain(source, refreshTimeout, JWK_CACHE_TIME_TO_LIVE);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private CachingJWKSetSource<SecurityContext> chain(JWKSetSource<SecurityContext> source, long refreshTimeout, long timeToLive) {
        EventListener l = listener;
        RetryingJWKSetSource<SecurityContext> retrying = new RetryingJWKSetSource<>(source, l);
        OutageTolerantJWKSetSource<SecurityContext> outageTolerant = new OutageTolerantJWKSetSource<>(retrying, OUTAGE_CACHE_TIME_TO_LIVE, l);
        return new CachingJWKSetSource<>(outageTolerant, timeToLive, refreshTimeout, l);
    }

    // (re)load the JWK set at the given (simulated) time; forces a refresh of the previously returned JWK set
    // (the outage cache is not used with forceRefresh(), so reference comparison is used instead)
    private void refreshAt(long time) {
        JWKSetCacheRefreshEvaluator evaluator = previous == null ? JWKSetCacheRefreshEvaluator.noRefresh() : JWKSetCacheRefreshEvaluator.referenceComparison(previous);
        try {
            previous = chain.getJWKSet(evaluator, time, null);
        } catch (Exception e) {
            // failure without outage cache
        }
    }

    private List<String> warnings() {
        return logAppender.list.stream().filter(e -> e.getLevel().isGreaterOrEqual(Level.WARN)).map(ILoggingEvent::getFormattedMessage).toList();
    }

    @BeforeEach
    void setUpLogCapture() {
        logAppender.start();
        ((Logger) LoggerFactory.getLogger(DecodedJwtCacheJwkEventListener.class)).addAppender(logAppender);
    }

    @AfterEach
    void tearDown() {
        ((Logger) LoggerFactory.getLogger(DecodedJwtCacheJwkEventListener.class)).detachAppender(logAppender);
        decoder.close();
    }

    @Test
    void testListenerExceptionIsNotPropagatedAndSuspendsCache() {
        // i.e. a bug in the cache; the JWK refresh (and the request which triggered it) must not fail
        DecodedJwtCacheJwtDecoder failing = new DecodedJwtCacheJwtDecoder(token -> {
            throw new IllegalStateException("Not used");
        }, jwt -> OAuth2TokenValidatorResult.success(), 0, 10) {
            @Override
            public void updateKeys(JWKSet jwkSet) {
                throw new IllegalStateException("Simulated cache failure");
            }
        };
        try {
            DecodedJwtCacheJwkEventListener failingListener = new DecodedJwtCacheJwkEventListener(failing);
            assertThat(failing.isSuspended()).isFalse();

            JwkEvents.refresh(failingListener, jwkSet);

            assertThat(failing.isSuspended()).isTrue();
            assertThat(logAppender.list).anyMatch(e -> e.getLevel() == Level.ERROR && e.getFormattedMessage().contains("RefreshCompletedEvent"));
        } finally {
            failing.close();
        }
    }

    @Test
    void testWarnsAtHalfAndThreeQuartersOfJwkOutageCacheTimeToLive() {
        refreshAt(0);
        source.setFail(true);

        refreshAt(100); // 10%
        assertThat(warnings()).isEmpty();

        refreshAt(500); // 50%
        assertThat(warnings()).hasSize(1);
        assertThat(warnings().get(0)).contains("50%", "500 ms left");

        refreshAt(600); // 60%, already warned
        assertThat(warnings()).hasSize(1);

        refreshAt(800); // 80%
        assertThat(warnings()).hasSize(2);
        assertThat(warnings().get(1)).contains("75%", "200 ms left");

        refreshAt(900);
        assertThat(warnings()).hasSize(2);
    }

    @Test
    void testWarnsBothWhenFirstOutageEventIsLate() {
        refreshAt(0);
        source.setFail(true);

        refreshAt(900); // 90%
        assertThat(warnings()).hasSize(2);
    }

    @Test
    void testRefreshResetsWarnings() {
        refreshAt(0);
        source.setFail(true);
        refreshAt(900);
        assertThat(warnings()).hasSize(2);

        // successful refresh
        source.setFail(false);
        refreshAt(1000);

        // new outage
        source.setFail(true);
        refreshAt(1500);
        assertThat(warnings()).hasSize(3);
    }

    @Test
    void testRefreshUpdatesKeysAndResumes() {
        decoder.suspendAt(System.currentTimeMillis());
        assertThat(decoder.isSuspended()).isTrue();

        long before = System.currentTimeMillis();
        refreshAt(0);
        long after = System.currentTimeMillis();

        assertThat(decoder.cache.keyRepresentations.contains("kid1")).isTrue();
        assertThat(decoder.isSuspended()).isFalse();
        // trusted for as long as the JWK set is
        assertThat(decoder.suspendedAt).isBetween(before + JWK_CACHE_TIME_TO_LIVE, after + JWK_CACHE_TIME_TO_LIVE);
    }

    @Test
    void testSuspendedWhenJwkSetTimeToLiveExpiresWithoutEvents() throws Exception {
        // i.e. an on-demand refresh after the JWK set expired fails without the outage cache: no event is fired
        CachingJWKSetSource<SecurityContext> shortLived = chain(source, 1000, 20);
        shortLived.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), null);
        assertThat(decoder.isSuspended()).isFalse();

        Thread.sleep(50);

        assertThat(decoder.isSuspended()).isTrue();
    }

    @Test
    void testRefreshNotScheduledIsLogged() throws Exception {
        // refresh-ahead time + refresh timeout == time to live is accepted, but no refresh-ahead is ever scheduled
        RefreshAheadCachingJWKSetSource<SecurityContext> refreshAhead = new RefreshAheadCachingJWKSetSource<>(source, 1000, 200, 800, false, null);
        try {
            listener.notify(new RefreshAheadCachingJWKSetSource.RefreshNotScheduledEvent<>(refreshAhead, null));

            assertThat(warnings()).hasSize(1);
            assertThat(warnings().get(0)).contains("No JWK set refresh-ahead was scheduled");
            assertThat(decoder.isSuspended()).isFalse();
        } finally {
            refreshAhead.close();
        }
    }

    @Test
    void testRefreshServedFromJwkOutageCacheSuspendsWhenOutageCacheExpires() {
        refreshAt(0);
        source.setFail(true);

        long before = System.currentTimeMillis();
        refreshAt(400); // retried, then served from the JWK outage cache with 600 ms left
        long after = System.currentTimeMillis();

        assertThat(decoder.suspendedAt).isBetween(before + 600, after + 600);
        assertThat(decoder.isSuspended()).isFalse();
        assertThat(decoder.cache.keyRepresentations.contains("kid1")).isTrue();
    }

    @Test
    void testRefreshAfterOutageResumes() {
        refreshAt(0);
        source.setFail(true);
        refreshAt(400);
        assertThat(decoder.suspendedAt).isNotEqualTo(DecodedJwtCacheJwtDecoder.NEVER);

        source.setFail(false);
        long before = System.currentTimeMillis();
        refreshAt(500);

        assertThat(decoder.suspendedAt).isGreaterThanOrEqualTo(before + JWK_CACHE_TIME_TO_LIVE);
        assertThat(decoder.isSuspended()).isFalse();
    }

    @Test
    void testSuspendedWhenJwkOutageCacheExpires() throws Exception {
        refreshAt(0);
        source.setFail(true);

        refreshAt(OUTAGE_CACHE_TIME_TO_LIVE - 1); // 1 ms left
        Thread.sleep(5);
        assertThat(decoder.isSuspended()).isTrue();

        // past the JWK outage cache time to live, the JWK set is unavailable
        refreshAt(OUTAGE_CACHE_TIME_TO_LIVE + 1);
        assertThat(decoder.isSuspended()).isTrue();
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void testUnableToRefreshSuspendsNow() throws Exception {
        // a JWK set which is already expired when loaded: the refresh completes, but the JWK set cannot be used
        CachingJWKSetSource<SecurityContext> expiring = new CachingJWKSetSource<>(new TestJWKSetSource(jwkSet), 0, 1000, (EventListener) listener);

        assertThrows(Exception.class, () -> expiring.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), null));

        assertThat(decoder.isSuspended()).isTrue();
    }

    @Test
    void testFailedScheduledRefreshSuspendsNow() {
        listener.notify(new RefreshAheadCachingJWKSetSource.UnableToRefreshAheadOfExpirationEvent<>(chain, null));
        assertThat(decoder.isSuspended()).isTrue();

        decoder.resume();
        listener.notify(new RefreshAheadCachingJWKSetSource.ScheduledRefreshFailed<>(chain, new Exception("Simulated"), null));
        assertThat(decoder.isSuspended()).isTrue();
    }

    @Test
    void testIgnoresWaitingAndTimedOutRefresh() throws Exception {
        refreshAt(0);
        DecodedJwtCacheJwtDecoder.Cache cache = decoder.cache;

        // a slow refresh, and another thread giving up waiting for it
        TestJWKSetSource slowSource = new TestJWKSetSource(jwkSet);
        CachingJWKSetSource<SecurityContext> slow = chain(slowSource, 20);
        slowSource.block();
        Thread slowRefresh = new Thread(() -> {
            try {
                slow.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), null);
            } catch (Exception e) {
                // ignore
            }
        });
        slowRefresh.start();
        long deadline = System.currentTimeMillis() + 10_000;
        while (slowRefresh.getState() != Thread.State.TIMED_WAITING && System.currentTimeMillis() < deadline) {
            Thread.sleep(1);
        }

        // waits for the slow refresh (WaitingForRefreshEvent), then gives up (RefreshTimedOutEvent)
        assertThrows(Exception.class, () -> slow.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), null));

        assertThat(decoder.isSuspended()).isFalse();
        assertThat(decoder.cache).isSameAs(cache);

        slowSource.release();
        slowRefresh.join(10_000);
    }
}
