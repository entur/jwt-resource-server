package org.entur.jwt.spring.cache;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import java.util.ArrayList;
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

    @AfterEach
    void tearDown() {
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

    private static JWKSet jwkSet(String... kids) throws Exception {
        JWK[] keys = new JWK[kids.length];
        for (int i = 0; i < kids.length; i++) {
            keys[i] = key(kids[i]);
        }
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
        int decoderThreads = Math.max(1, Runtime.getRuntime().availableProcessors() - rotatorThreads);
        int iterationsPerDecoderThread = 50000;

        ExecutorService executor = Executors.newFixedThreadPool(decoderThreads + rotatorThreads);
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
    }
}
