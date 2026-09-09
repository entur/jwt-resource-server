package org.entur.jwt.spring.decode.cache;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class DecodedJwtCacheJwtDecoderTest {

    private static final long CLEANUP_INTERVAL = 24L * 60L * 60L * 1000L; // not used unless scheduleCleanup() is called
    private static final int MAX_TOKENS = 10000;

    private DecodedJwtCacheJwtDecoder decoder;
    private ListAppender<ILoggingEvent> logAppender;

    @BeforeEach
    void setUpLogCapture() {
        logAppender = new ListAppender<>();
        logAppender.start();
        loggerUnderTest().addAppender(logAppender);
    }

    private static Logger loggerUnderTest() {
        return (Logger) LoggerFactory.getLogger(DecodedJwtCacheJwtDecoder.class);
    }

    @AfterEach
    void tearDown() {
        loggerUnderTest().detachAppender(logAppender);
        if (decoder != null) {
            decoder.close();
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static Jwt jwt(String token, String kid) {
        return Jwt.withTokenValue(token)
                .header("kid", kid)
                .header("alg", "none")
                .claim("sub", "user")
                .build();
    }

    private static JWK key(String kid) throws Exception {
        return new OctetSequenceKey.Builder("secret-material".getBytes()).keyID(kid).build();
    }

    private static JWK key(String kid, String algorithm) throws Exception {
        return new OctetSequenceKey.Builder("secret-material".getBytes())
                .keyID(kid)
                .algorithm(new Algorithm(algorithm))
                .build();
    }

    private static JWK keyWithValidityWindow(String kid, Date notBefore, Date expirationTime) throws Exception {
        return new OctetSequenceKey.Builder("secret-material".getBytes())
                .keyID(kid)
                .notBeforeTime(notBefore)
                .expirationTime(expirationTime)
                .build();
    }

    private static JWKSet jwkSet(String... kids) throws Exception {
        JWK[] keys = new JWK[kids.length];
        for (int i = 0; i < kids.length; i++) {
            keys[i] = key(kids[i]);
        }
        return new JWKSet(List.of(keys));
    }

    private static JWKSet jwkSet(JWK... keys) {
        return new JWKSet(List.of(keys));
    }

    private static OAuth2TokenValidator<Jwt> alwaysValid() {
        return jwt -> OAuth2TokenValidatorResult.success();
    }

    private static OAuth2TokenValidator<Jwt> alwaysInvalid() {
        return jwt -> OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "expired", null));
    }

    @SuppressWarnings("unchecked")
    private static CachingJWKSetSource.RefreshCompletedEvent<?> refreshCompletedEvent(JWKSet jwkSet) {
        CachingJWKSetSource.RefreshCompletedEvent<?> event = mock(CachingJWKSetSource.RefreshCompletedEvent.class);
        when(event.getJWKSet()).thenReturn(jwkSet);
        return event;
    }

    private static CachingJWKSetSource.RefreshInitiatedEvent<?> refreshInitiatedEvent() {
        return mock(CachingJWKSetSource.RefreshInitiatedEvent.class);
    }

    private static CachingJWKSetSource.UnableToRefreshEvent<?> unableToRefreshEvent() {
        return mock(CachingJWKSetSource.UnableToRefreshEvent.class);
    }

    private static CachingJWKSetSource.RefreshTimedOutEvent<?> refreshTimedOutEvent() {
        return mock(CachingJWKSetSource.RefreshTimedOutEvent.class);
    }

    // -----------------------------------------------------------------------
    // Basic decode / caching behaviour
    // -----------------------------------------------------------------------

    @Test
    void decodesViaDelegateWhenCacheEmpty() {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);

        Jwt result = decoder.decode("token1");

        assertSame(jwt, result);
        verify(delegate, times(1)).decode("token1");
    }

    @Test
    void doesNotCacheJwtWithUnknownKeyId() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "unknown-kid");
        when(delegate.decode("token1")).thenReturn(jwt);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        decoder.decode("token1");
        decoder.decode("token1");

        // key id unknown to the cache -> never cached -> delegate invoked every time
        verify(delegate, times(2)).decode("token1");
    }

    @Test
    void cachesJwtWithKnownKeyIdAndAvoidsRedecoding() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        Jwt first = decoder.decode("token1");
        Jwt second = decoder.decode("token1");

        assertSame(jwt, first);
        assertSame(jwt, second);
        verify(delegate, times(1)).decode("token1");
    }

    @Test
    @SuppressWarnings("unchecked")
    void reValidatesCachedJwtOnEveryDecode() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        OAuth2TokenValidator<Jwt> validator = mock(OAuth2TokenValidator.class);
        when(validator.validate(any())).thenReturn(OAuth2TokenValidatorResult.success());

        decoder = new DecodedJwtCacheJwtDecoder(delegate, validator, CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        decoder.decode("token1");
        decoder.decode("token1");

        // decoded once via delegate, but the cache-hit path must still re-validate
        // on every subsequent call
        verify(validator, times(1)).validate(jwt);
    }

    @Test
    void throwsAndEvictsWhenCachedJwtFailsRevalidation() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysInvalid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        // first call goes straight to the delegate (which "already validates"), so it
        // is cached without going through validateJwt()
        decoder.decode("token1");

        // second call is a cache hit and re-validates -> fails and evicts the entry
        assertThrows(JwtValidationException.class, () -> decoder.decode("token1"));

        // third decode should hit delegate again since the invalid entry was evicted
        decoder.decode("token1");
        verify(delegate, times(2)).decode("token1");
    }

    @Test
    void propagatesDelegateExceptions() {
        JwtDecoder delegate = mock(JwtDecoder.class);
        when(delegate.decode(anyString())).thenThrow(new JwtException("bad token"));

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);

        assertThrows(JwtException.class, () -> decoder.decode("token1"));
    }

    // -----------------------------------------------------------------------
    // maxCacheSize enforcement
    // -----------------------------------------------------------------------

    @Test
    void neverCachesMoreThanMaxCacheSize() throws Exception {
        int maxCacheSize = 5;
        int distinctTokens = 50;

        JwtDecoder delegate = mock(JwtDecoder.class);
        when(delegate.decode(anyString())).thenAnswer(invocation -> {
            String token = invocation.getArgument(0);
            return jwt(token, "kid1");
        });

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, maxCacheSize);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        for (int i = 0; i < distinctTokens; i++) {
            decoder.decode("token-" + i);
            assertTrue(decoder.getSize() <= maxCacheSize,
                    "cache size " + decoder.getSize() + " must never exceed maxCacheSize " + maxCacheSize);
        }

        assertEquals(maxCacheSize, decoder.getSize(), "cache should have filled up to the configured limit");
    }

    @Test
    void stopsCachingNewEntriesOnceMaxCacheSizeIsReachedButKeepsServingCachedOnes() throws Exception {
        int maxCacheSize = 2;

        JwtDecoder delegate = mock(JwtDecoder.class);
        when(delegate.decode(anyString())).thenAnswer(invocation -> {
            String token = invocation.getArgument(0);
            return jwt(token, "kid1");
        });

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, maxCacheSize);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        // fill the cache to its limit
        decoder.decode("token-0");
        decoder.decode("token-1");
        assertEquals(maxCacheSize, decoder.getSize());

        // already-cached entries are still served from cache
        decoder.decode("token-0");
        decoder.decode("token-1");
        verify(delegate, times(1)).decode("token-0");
        verify(delegate, times(1)).decode("token-1");

        // cache is full -> new entries are not added, delegate is invoked every time
        decoder.decode("token-2");
        decoder.decode("token-2");
        assertEquals(maxCacheSize, decoder.getSize());
        verify(delegate, times(2)).decode("token-2");
    }

    @Test
    void unboundedCacheSizeAllowsGrowthBeyondDefault() throws Exception {
        int distinctTokens = 500;

        JwtDecoder delegate = mock(JwtDecoder.class);
        when(delegate.decode(anyString())).thenAnswer(invocation -> {
            String token = invocation.getArgument(0);
            return jwt(token, "kid1");
        });

        // -1 disables the cap (translated internally to Integer.MAX_VALUE)
        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, -1);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        for (int i = 0; i < distinctTokens; i++) {
            decoder.decode("token-" + i);
        }

        assertEquals(distinctTokens, decoder.getSize());
    }

    // -----------------------------------------------------------------------
    // clear()
    // -----------------------------------------------------------------------

    @Test
    void clearRemovesCachedEntries() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        decoder.decode("token1");
        decoder.clear();
        decoder.decode("token1");

        verify(delegate, times(2)).decode("token1");
    }

    // -----------------------------------------------------------------------
    // cleanup()
    // -----------------------------------------------------------------------

    @Test
    void cleanupDoesNothingWhenCacheIsEmpty() {
        JwtDecoder delegate = mock(JwtDecoder.class);

        OAuth2TokenValidator<Jwt> validator = mock(OAuth2TokenValidator.class);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, validator, CLEANUP_INTERVAL, MAX_TOKENS);

        decoder.cleanup();

        // nothing cached -> validator should never be invoked by cleanup
        verifyNoInteractions(validator);
        assertEquals(0, decoder.getSize());
    }

    @Test
    void cleanupRemovesInvalidJwtsFromCache() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysInvalid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        // cached without going through validateJwt(), since the delegate already validates it
        decoder.decode("token1");
        assertEquals(1, decoder.getSize());

        decoder.cleanup();

        // the invalid entry should have been evicted by cleanup()
        assertEquals(0, decoder.getSize());

        // subsequent decode must hit the delegate again since the cache entry is gone
        decoder.decode("token1");
        verify(delegate, times(2)).decode("token1");
    }

    @Test
    void cleanupKeepsStillValidJwtsInCache() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        decoder.decode("token1");
        assertEquals(1, decoder.getSize());

        decoder.cleanup();

        // still valid -> not evicted
        assertEquals(1, decoder.getSize());
        decoder.decode("token1");
        verify(delegate, times(1)).decode("token1");
    }

    @Test
    @SuppressWarnings("unchecked")
    void cleanupSwallowsExceptionsThrownByValidator() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        OAuth2TokenValidator<Jwt> validator = mock(OAuth2TokenValidator.class);
        // decode() itself is not affected by the validator mock since the delegate "already validates",
        // so the first call just caches the entry
        when(validator.validate(any())).thenThrow(new RuntimeException("MOCK EXCEPTION"));

        decoder = new DecodedJwtCacheJwtDecoder(delegate, validator, CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        decoder.decode("token1");
        assertEquals(1, decoder.getSize());

        // cleanup() must not propagate exceptions raised while revalidating cached entries
        assertDoesNotThrow(() -> decoder.cleanup());
    }

    @Test
    void scheduleCleanupPeriodicallyEvictsInvalidJwts() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        long shortCleanupInterval = 20L;
        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysInvalid(), shortCleanupInterval, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        decoder.decode("token1");
        assertEquals(1, decoder.getSize());

        decoder.scheduleCleanup();

        long deadline = System.currentTimeMillis() + 5000L;
        while (decoder.getSize() != 0 && System.currentTimeMillis() < deadline) {
            Thread.sleep(20L);
        }

        assertEquals(0, decoder.getSize(), "background cleanup should have evicted the invalid entry");
    }

    @Test
    void scheduleCleanupIsNoOpWhenCleanupIntervalIsNotPositive() {
        JwtDecoder delegate = mock(JwtDecoder.class);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), 0L, MAX_TOKENS);

        // must not throw and must not schedule anything against the executor
        assertDoesNotThrow(() -> decoder.scheduleCleanup());
    }

    // -----------------------------------------------------------------------
    // notify() / key id rotation
    // -----------------------------------------------------------------------

    @Test
    void refreshInitiatedAndUnableToRefreshAndTimedOutEventsAreNoOps() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        decoder.decode("token1");

        decoder.notify(refreshInitiatedEvent());
        decoder.notify(unableToRefreshEvent());
        decoder.notify(refreshTimedOutEvent());

        // still cached, none of the above events should have evicted anything
        decoder.decode("token1");
        verify(delegate, times(1)).decode("token1");
    }

    // -----------------------------------------------------------------------
    // notify() / refresh outage handling (UnableToRefreshEvent, RefreshTimedOutEvent)
    // -----------------------------------------------------------------------

    @Test
    void outageLogsWarningAtHalfAndThreeQuartersOfTimeToLive() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        long outageTimeToLiveMillis = 200L;
        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS, true, outageTimeToLiveMillis);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        decoder.decode("token1"); // cached

        // still well within the tolerated window -> no warnings yet
        decoder.notify(unableToRefreshEvent());
        assertTrue(logAppender.list.isEmpty());

        // past 50% -> one warning noting time left
        Thread.sleep((outageTimeToLiveMillis * 6) / 10);
        decoder.notify(unableToRefreshEvent());
        assertEquals(1, logAppender.list.size());
        assertTrue(logAppender.list.get(0).getFormattedMessage().contains("50%"));

        // repeated notifications while still under 75% must not log again
        decoder.notify(unableToRefreshEvent());
        assertEquals(1, logAppender.list.size());

        // past 75% -> a second, distinct warning
        Thread.sleep((outageTimeToLiveMillis * 2) / 10);
        decoder.notify(refreshTimedOutEvent());
        assertEquals(2, logAppender.list.size());
        assertTrue(logAppender.list.get(1).getFormattedMessage().contains("75%"));

        // cache is still tolerated - not yet flushed
        decoder.decode("token1");
        verify(delegate, times(1)).decode("token1");
    }

    @Test
    void outageWarningsAreNotLoggedWhenOutageCacheDisabled() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS, false, -1L);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        decoder.notify(unableToRefreshEvent());

        assertTrue(logAppender.list.isEmpty());
    }

    @Test
    void outageWarningsAreNotLoggedWhenOutageToleratedIndefinitely() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS, true, -1L);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        decoder.notify(unableToRefreshEvent());
        Thread.sleep(50L);
        decoder.notify(refreshTimedOutEvent());

        assertTrue(logAppender.list.isEmpty());
    }

    @Test
    void successfulRefreshResetsOutageWarningState() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        long outageTimeToLiveMillis = 100L;
        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS, true, outageTimeToLiveMillis);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        Thread.sleep((outageTimeToLiveMillis * 6) / 10);
        decoder.notify(unableToRefreshEvent());
        assertEquals(1, logAppender.list.size());

        // a successful refresh resets the outage clock and the warning flags
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));
        logAppender.list.clear();

        decoder.notify(unableToRefreshEvent());
        assertTrue(logAppender.list.isEmpty());
    }

    @Test
    void unableToRefreshEventFlushesCacheImmediatelyWhenOutageCacheDisabled() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS, false, -1L);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        decoder.decode("token1"); // cached

        decoder.notify(unableToRefreshEvent());

        // outage cache disabled -> flushed immediately, even though this is the first sign of trouble
        decoder.decode("token1");
        verify(delegate, times(2)).decode("token1");
    }

    @Test
    void refreshTimedOutEventFlushesCacheImmediatelyWhenOutageCacheDisabled() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS, false, -1L);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        decoder.decode("token1"); // cached

        decoder.notify(refreshTimedOutEvent());

        decoder.decode("token1");
        verify(delegate, times(2)).decode("token1");
    }

    @Test
    void outageIsToleratedUntilItLastsLongerThanConfiguredTimeToLive() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        long outageTimeToLiveMillis = 50L;
        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS, true, outageTimeToLiveMillis);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        decoder.decode("token1"); // cached

        // first sign of trouble; still well within the tolerated outage window
        decoder.notify(unableToRefreshEvent());
        decoder.decode("token1");
        verify(delegate, times(1)).decode("token1");

        // let the outage run past the configured time to live, then observe another
        // failed refresh attempt -> the cache must now be flushed
        Thread.sleep(outageTimeToLiveMillis * 3);
        decoder.notify(refreshTimedOutEvent());

        decoder.decode("token1");
        verify(delegate, times(2)).decode("token1");
    }

    @Test
    void outageCacheToleratesOutageIndefinitelyWhenTimeToLiveIsNegative() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS, true, -1L);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        decoder.decode("token1"); // cached

        decoder.notify(unableToRefreshEvent());
        Thread.sleep(50L);
        decoder.notify(refreshTimedOutEvent());

        // negative time to live -> outage tolerated forever, cache never auto-flushed
        decoder.decode("token1");
        verify(delegate, times(1)).decode("token1");
    }

    @Test
    void successfulRefreshResetsAnOngoingOutage() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        long outageTimeToLiveMillis = 50L;
        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS, true, outageTimeToLiveMillis);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        decoder.decode("token1"); // cached

        decoder.notify(unableToRefreshEvent());
        Thread.sleep(outageTimeToLiveMillis * 3);

        // a successful refresh in between resets the outage clock, even though the keys
        // themselves are unchanged and would otherwise keep the cache as-is
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));
        decoder.notify(unableToRefreshEvent());

        decoder.decode("token1");
        verify(delegate, times(1)).decode("token1");
    }

    @Test
    void refreshCompletedWithSameKeyIdsKeepsCache() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        decoder.decode("token1");

        // refresh completes again with the very same key ids
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        decoder.decode("token1");
        verify(delegate, times(1)).decode("token1");
    }

    @Test
    void refreshCompletedWithNewKeyIdsEvictsJwtsWithUnknownKeyIds() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt1 = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt1);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        decoder.decode("token1"); // cached under kid1

        // JWKS rotates: kid1 no longer present, kid2 introduced
        decoder.notify(refreshCompletedEvent(jwkSet("kid2")));

        decoder.decode("token1");
        verify(delegate, times(2)).decode("token1");
    }

    @Test
    void refreshCompletedWithOverlappingKeyIdsRetainsStillValidJwts() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt1 = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt1);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1", "kid2")));

        decoder.decode("token1"); // cached under kid1

        // JWKS rotates: kid1 retained, kid3 added -> key id set changed, but kid1 still known
        decoder.notify(refreshCompletedEvent(jwkSet("kid1", "kid3")));

        decoder.decode("token1");
        verify(delegate, times(1)).decode("token1");
    }

    @Test
    void refreshCompletedWithChangedJwkMetadataEvictsCachedJwt() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt1 = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt1);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet(key("kid1", "HS256"))));

        decoder.decode("token1"); // cached under kid1

        // same key material and kid, but metadata changed in a way that can affect key selection
        decoder.notify(refreshCompletedEvent(jwkSet(key("kid1", "HS512"))));

        decoder.decode("token1");
        verify(delegate, times(2)).decode("token1");
    }

    @Test
    void refreshCompletedWithDuplicateKidCachesJwtButEvictsAllOnAnyChange() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt1 = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt1);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet(key("kid1", "HS256"), key("kid1", "HS512"))));

        // multiple JWKs may legally share the same kid; the kid is still active and
        // can be cached even though it's ambiguous which of the keys signed the JWT
        decoder.decode("token1");
        decoder.decode("token1");
        verify(delegate, times(1)).decode("token1");

        // if any of the keys sharing that kid changes (here: one of the two variants
        // is dropped), the whole group for that kid must be considered changed,
        // evicting anything cached under it
        decoder.notify(refreshCompletedEvent(jwkSet(key("kid1", "HS256"))));

        decoder.decode("token1");
        verify(delegate, times(2)).decode("token1");
    }

    // -----------------------------------------------------------------------
    // notify() / JWK "nbf" (notBefore) and "exp" (expirationTime) validity window
    // -----------------------------------------------------------------------

    @Test
    void refreshCompletedIgnoresKeyThatIsNotYetValid() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt1 = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt1);

        Date oneHourFromNow = new Date(System.currentTimeMillis() + 3600_000L);
        JWK notYetValidKey = keyWithValidityWindow("kid1", oneHourFromNow, null);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet(notYetValidKey)));

        // kid1's "nbf" is in the future -> not treated as an active key -> never cached
        decoder.decode("token1");
        decoder.decode("token1");
        verify(delegate, times(2)).decode("token1");
    }

    @Test
    void refreshCompletedIgnoresKeyThatHasExpired() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt1 = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt1);

        Date oneHourAgo = new Date(System.currentTimeMillis() - 3600_000L);
        JWK expiredKey = keyWithValidityWindow("kid1", null, oneHourAgo);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet(expiredKey)));

        // kid1's "exp" is in the past -> not treated as an active key -> never cached
        decoder.decode("token1");
        decoder.decode("token1");
        verify(delegate, times(2)).decode("token1");
    }

    @Test
    void refreshCompletedAcceptsKeyCurrentlyWithinItsValidityWindow() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt1 = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt1);

        Date oneHourAgo = new Date(System.currentTimeMillis() - 3600_000L);
        Date oneHourFromNow = new Date(System.currentTimeMillis() + 3600_000L);
        JWK currentlyValidKey = keyWithValidityWindow("kid1", oneHourAgo, oneHourFromNow);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet(currentlyValidKey)));

        // "now" is within [nbf, exp] -> key is active -> cached as usual
        decoder.decode("token1");
        decoder.decode("token1");
        verify(delegate, times(1)).decode("token1");
    }

    @Test
    void refreshCompletedEvictsCachedJwtWhenItsKeyBecomesNotYetValidAgain() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt1 = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwt1);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1"))); // no validity window -> always active

        decoder.decode("token1"); // cached under kid1

        // JWKS refreshes and now advertises kid1 with a future "nbf" (e.g. a
        // pre-published upcoming key reusing an old kid) -> must be treated as
        // a different/inactive key, evicting anything cached under that kid
        Date oneHourFromNow = new Date(System.currentTimeMillis() + 3600_000L);
        decoder.notify(refreshCompletedEvent(jwkSet(keyWithValidityWindow("kid1", oneHourFromNow, null))));

        decoder.decode("token1");
        verify(delegate, times(2)).decode("token1");
    }

    // -----------------------------------------------------------------------
    // notify() using a real-world JWKS (Auth0 tenant partner.dev.entur.org)
    //
    // The fixture in src/test/resources/.../auth0-partner-dev-jwks.json is a
    // frozen snapshot fetched from
    // https://partner.dev.entur.org/.well-known/jwks.json on 2026-09-09, used
    // here only as realistic fixture data (real RSA "n"/"e", "x5c" cert chain,
    // "x5t" thumbprint, "alg"/"use" fields) that the synthetic HMAC JWKs used
    // elsewhere in this file don't exercise.
    //
    // Time-variant fields / caveats for future maintainers:
    //  - The set of keys itself is time-variant: Auth0 rotates/retires signing
    //    keys over time, so this snapshot will eventually no longer match the
    //    live endpoint. Do not assert this JSON is "current" or fetch it live
    //    in the test (no network calls in unit tests) - it is reference data.
    //  - Individual JWK entries have no exp/iat-like field of their own, so
    //    nothing here changes merely with wall-clock time.
    //  - Each "x5c" certificate embeds its own notBefore/notAfter validity
    //    window (2018-04-27/2032-01-04 for AUTH0_KID_1, 2020-03-17/2033-11-24
    //    for AUTH0_KID_2 at fetch time). This decoder does not itself validate
    //    those certificate timestamps, but they are part of the "x5c" bytes
    //    that feed into the full-JWK-representation comparison, so
    //    refreshCompletedWithUnchangedAuth0JwksIncludingCertValidityKeepsCache
    //    below explicitly re-parses the fixture and checks that notBefore/
    //    notAfter come out identical across parses, and that such a
    //    genuinely-unchanged refresh does NOT evict the cache.
    //  - Note kid conventions are inconsistent even within this one tenant:
    //    AUTH0_KID_1 happens to equal its own "x5t" (cert SHA-1 thumbprint),
    //    while AUTH0_KID_2 does not. A future cert renewal could reuse a kid
    //    while changing "x5c"/"x5t" (or vice versa) - exactly the scenario
    //    the full-JWK-representation comparison below is meant to catch,
    //    rather than relying on kid alone.
    private static final String AUTH0_KID_1 = "N0JDNjBGMUJCQzlDMDVERTE4NTI4MDA0NzU3MUQ0QzJBNTM1MjhCNw";
    private static final String AUTH0_KID_2 = "DL_LhIMfNWaGymXRjFEWG";

    private static String readClasspathResourceToString(String path) throws java.io.IOException {
        try (java.io.InputStream in = DecodedJwtCacheJwtDecoderTest.class.getResourceAsStream(path)) {
            if (in == null) {
                throw new java.io.FileNotFoundException("Classpath resource not found: " + path);
            }
            return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    private static JWKSet auth0JwkSet() throws Exception {
        String json = readClasspathResourceToString("auth0-partner-dev-jwks.json");
        return JWKSet.parse(json);
    }

    private static java.security.cert.X509Certificate leafCertificate(JWK key) throws Exception {
        RSAKey rsaKey = (RSAKey) key;
        return com.nimbusds.jose.util.X509CertChainUtils.parse(rsaKey.getX509CertChain()).get(0);
    }

    @Test
    void cachesJwtsSignedWithRealAuth0PublicKeysWhileBothPresent() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt1 = jwt("token1", AUTH0_KID_1);
        Jwt jwt2 = jwt("token2", AUTH0_KID_2);
        when(delegate.decode("token1")).thenReturn(jwt1);
        when(delegate.decode("token2")).thenReturn(jwt2);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(auth0JwkSet()));

        decoder.decode("token1");
        decoder.decode("token2");
        decoder.decode("token1");
        decoder.decode("token2");

        // both real kids are known -> both get cached and only decoded once each
        verify(delegate, times(1)).decode("token1");
        verify(delegate, times(1)).decode("token2");
    }

    @Test
    void refreshCompletedWhenRealAuth0KeyIsRotatedAwayEvictsOnlyThatKeysCachedJwt() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt1 = jwt("token1", AUTH0_KID_1);
        Jwt jwt2 = jwt("token2", AUTH0_KID_2);
        when(delegate.decode("token1")).thenReturn(jwt1);
        when(delegate.decode("token2")).thenReturn(jwt2);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(auth0JwkSet()));

        decoder.decode("token1"); // cached under AUTH0_KID_1
        decoder.decode("token2"); // cached under AUTH0_KID_2

        // Auth0 rotates away the older key (AUTH0_KID_1), keeping only AUTH0_KID_2
        JWK retainedKey = auth0JwkSet().getKeyByKeyId(AUTH0_KID_2);
        decoder.notify(refreshCompletedEvent(new JWKSet(retainedKey)));

        decoder.decode("token1"); // AUTH0_KID_1 no longer known -> re-decoded
        decoder.decode("token2"); // AUTH0_KID_2 still known -> still cached

        verify(delegate, times(2)).decode("token1");
        verify(delegate, times(1)).decode("token2");
    }

    @Test
    void refreshCompletedWithRealAuth0KeyCertRenewalEvictsCachedJwt() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt1 = jwt("token1", AUTH0_KID_2);
        when(delegate.decode("token1")).thenReturn(jwt1);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(auth0JwkSet()));

        decoder.decode("token1"); // cached under AUTH0_KID_2

        // simulate a certificate renewal that keeps the same kid and RSA key
        // material (n/e) but replaces the x5c chain / x5t thumbprint, which is
        // a realistic thing for an IdP to do (e.g. yearly cert reissue against
        // the same key pair) and is exactly the sort of change a kid-only or
        // thumbprint-only comparison would miss
        RSAKey original = (RSAKey) auth0JwkSet().getKeyByKeyId(AUTH0_KID_2);
        RSAKey renewedCert = new RSAKey.Builder(original)
                .x509CertChain(null)
                .x509CertThumbprint(null)
                .build();
        decoder.notify(refreshCompletedEvent(new JWKSet(renewedCert)));

        decoder.decode("token1");
        verify(delegate, times(2)).decode("token1");
    }

    @Test
    void refreshCompletedWithUnchangedAuth0JwksIncludingCertValidityKeepsCache() throws Exception {
        // parse the same fixture independently twice, as if it had been fetched
        // on two separate (unrelated) JWKS refreshes with no actual key rotation
        JWKSet firstRefresh = auth0JwkSet();
        JWKSet secondRefresh = auth0JwkSet();

        // the embedded x5c certificate's notBefore/notAfter validity window is
        // taken into account (it is part of the x5c bytes compared as part of
        // the full JWK representation), but since it genuinely did not change
        // between the two parses, it must not by itself trigger cache eviction
        java.security.cert.X509Certificate firstCert = leafCertificate(firstRefresh.getKeyByKeyId(AUTH0_KID_2));
        java.security.cert.X509Certificate secondCert = leafCertificate(secondRefresh.getKeyByKeyId(AUTH0_KID_2));
        assertEquals(firstCert.getNotBefore(), secondCert.getNotBefore());
        assertEquals(firstCert.getNotAfter(), secondCert.getNotAfter());

        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwt1 = jwt("token1", AUTH0_KID_2);
        when(delegate.decode("token1")).thenReturn(jwt1);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(firstRefresh));

        decoder.decode("token1"); // cached under AUTH0_KID_2

        // refresh completes again with an independently-parsed but content-identical
        // JWKS (same notBefore/notAfter, same everything else) -> cache is retained
        decoder.notify(refreshCompletedEvent(secondRefresh));

        decoder.decode("token1");
        verify(delegate, times(1)).decode("token1");
    }

    // -----------------------------------------------------------------------
    // Multithreaded: decode() concurrently with JWKS rotation via notify()
    // -----------------------------------------------------------------------

    @Test
    void concurrentDecodeAndKeyRotationNeverThrowsOrCorruptsState() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);

        // delegate always returns a freshly-"decoded" Jwt tagged with whichever kid is
        // currently active, simulating a real decoder that trusts the current JWKS
        AtomicInteger activeKid = new AtomicInteger(0);
        when(delegate.decode(anyString())).thenAnswer(invocation -> {
            String token = invocation.getArgument(0);
            return jwt(token, "kid" + (activeKid.get() % 3));
        });

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet("kid0", "kid1", "kid2")));

        int rotatorThreads = 2;
        int decoderThreads = Math.min(8, Math.max(1, Runtime.getRuntime().availableProcessors() - rotatorThreads));
        int iterationsPerDecoderThread = 50000;

        ExecutorService executor = Executors.newFixedThreadPool(decoderThreads + rotatorThreads);
        try {
            CountDownLatch start = new CountDownLatch(1);
            AtomicInteger errors = new AtomicInteger();

            List<Future<?>> futures = new ArrayList<>();

            for (int t = 0; t < decoderThreads; t++) {
                final int threadIndex = t;
                futures.add(executor.submit(() -> {
                    try {
                        start.await();
                        for (int i = 0; i < iterationsPerDecoderThread; i++) {
                            String token = "token-" + threadIndex + "-" + (i % 10);
                            try {
                                decoder.decode(token);
                            } catch (JwtException e) {
                                errors.incrementAndGet();
                            }
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }));
            }

            for (int t = 0; t < rotatorThreads; t++) {
                futures.add(executor.submit(() -> {
                    try {
                        start.await();
                        for (int i = 0; i < 100; i++) {
                            int next = activeKid.incrementAndGet() % 3;
                            try {
                                decoder.notify(refreshCompletedEvent(jwkSet("kid" + next, "kid" + ((next + 1) % 3))));
                            } catch (Exception e) {
                                errors.incrementAndGet();
                            }
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }));
            }

            start.countDown();

            for (Future<?> future : futures) {
                future.get(60, TimeUnit.SECONDS);
            }
            executor.shutdown();
            assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS));

            assertEquals(0, errors.get(), "decode()/notify() should never throw unexpectedly under concurrent access");
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void concurrentDecodeReturnsConsistentResultsDuringSingleKeyRotation() throws Exception {
        JwtDecoder delegate = mock(JwtDecoder.class);
        Jwt jwtKid1 = jwt("token1", "kid1");
        when(delegate.decode("token1")).thenReturn(jwtKid1);

        decoder = new DecodedJwtCacheJwtDecoder(delegate, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS);
        decoder.notify(refreshCompletedEvent(jwkSet("kid1")));

        // warm the cache
        decoder.decode("token1");

        int threads = Runtime.getRuntime().availableProcessors() * 4;
        ExecutorService executor = Executors.newFixedThreadPool(threads + 1);
        try {
            CountDownLatch start = new CountDownLatch(1);
            AtomicInteger errors = new AtomicInteger();

            List<Future<?>> futures = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                futures.add(executor.submit(() -> {
                    try {
                        start.await();
                        for (int i = 0; i < 50000; i++) {
                            Jwt result = decoder.decode("token1");
                            if (result == null || !"kid1".equals(result.getHeaders().get("kid"))) {
                                errors.incrementAndGet();
                            }
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } catch (JwtException e) {
                        errors.incrementAndGet();
                    }
                }));
            }

            // rotate the JWKS once concurrently, keeping kid1 known throughout so the
            // in-flight decode() calls should never fail
            futures.add(executor.submit(() -> {
                try {
                    start.await();
                    decoder.notify(refreshCompletedEvent(jwkSet("kid1", "kid2")));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));

            start.countDown();

            for (Future<?> future : futures) {
                future.get(60, TimeUnit.SECONDS);
            }
            executor.shutdown();
            assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS));

            assertEquals(0, errors.get());
        } finally {
            executor.shutdownNow();
        }
    }
}
