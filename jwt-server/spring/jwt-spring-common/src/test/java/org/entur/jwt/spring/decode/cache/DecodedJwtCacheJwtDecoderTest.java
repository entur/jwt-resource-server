package org.entur.jwt.spring.decode.cache;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSetBasedJWKSource;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import org.entur.jwt.spring.properties.jwk.JwtDecoderCacheMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class DecodedJwtCacheJwtDecoderTest {

    private static final long CLEANUP_INTERVAL = 24L * 60L * 60L * 1000L; // not used unless scheduleCleanup() is called
    private static final int MAX_TOKENS = 10000;

    private static ECKey key1;
    private static ECKey key2;
    // a new key under the same key id as key1
    private static ECKey rotatedKey1;

    // the JWK set (as the decoder's JWK source would load it)
    private TestJWKSetSource jwkSetSource;
    private JWKSource<SecurityContext> jwkSource;

    private DecodedJwtCacheJwtDecoder decoder;

    @BeforeAll
    static void createKeys() throws Exception {
        key1 = new ECKeyGenerator(Curve.P_256).keyID("kid1").generate();
        key2 = new ECKeyGenerator(Curve.P_256).keyID("kid2").generate();
        rotatedKey1 = new ECKeyGenerator(Curve.P_256).keyID("kid1").generate();
    }

    @BeforeEach
    void setUp() {
        jwkSetSource = new TestJWKSetSource(jwkSet(key1));
        jwkSource = new JWKSetBasedJWKSource<>(jwkSetSource);
    }

    @AfterEach
    void tearDown() {
        if (decoder != null) {
            decoder.close();
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    // a token signed with the given key id (the signature is not verified by the test delegate)
    private static String token(String kid, String name) {
        String header = kid != null ? "{\"alg\":\"ES256\",\"kid\":\"" + kid + "\"}" : "{\"alg\":\"ES256\"}";
        return Base64URL.encode(header) + "." + Base64URL.encode(name) + ".signature";
    }

    private static String token(String name) {
        return token("kid1", name);
    }

    private static Jwt jwt(String token) {
        return Jwt.withTokenValue(token)
                .header("alg", "ES256")
                .claim("sub", "user")
                .build();
    }

    // public keys, as new instances (like a reloaded JWK set)
    private static JWKSet jwkSet(ECKey... keys) {
        return new JWKSet(Arrays.stream(keys).map(key -> (JWK) key.toPublicJWK()).toList());
    }

    private static TestJwtDecoder delegate() {
        return new TestJwtDecoder().answering(DecodedJwtCacheJwtDecoderTest::jwt);
    }

    private DecodedJwtCacheJwtDecoder decoder(TestJwtDecoder delegate) {
        return decoder(delegate, alwaysValid());
    }

    private DecodedJwtCacheJwtDecoder decoder(TestJwtDecoder delegate, OAuth2TokenValidator<Jwt> validator) {
        decoder = new DecodedJwtCacheJwtDecoder(delegate, jwkSource, validator, CLEANUP_INTERVAL, MAX_TOKENS);
        return decoder;
    }

    private static OAuth2TokenValidator<Jwt> alwaysValid() {
        return jwt -> OAuth2TokenValidatorResult.success();
    }

    private static OAuth2TokenValidator<Jwt> alwaysInvalid() {
        return jwt -> OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "expired", null));
    }

    // -----------------------------------------------------------------------
    // Basic decode / caching behaviour
    // -----------------------------------------------------------------------

    @Test
    void decodesViaDelegateWhenCacheEmpty() {
        TestJwtDecoder delegate = new TestJwtDecoder();
        Jwt jwt = jwt(token("token1"));
        delegate.returning(token("token1"), jwt);
        decoder(delegate);

        Jwt result = decoder.decode(token("token1"));

        assertSame(jwt, result);
        assertEquals(1, delegate.count(token("token1")));
    }

    @Test
    void cachesJwtAndAvoidsRedecoding() {
        TestJwtDecoder delegate = new TestJwtDecoder();
        Jwt jwt = jwt(token("token1"));
        delegate.returning(token("token1"), jwt);
        decoder(delegate);

        Jwt first = decoder.decode(token("token1"));
        Jwt second = decoder.decode(token("token1"));

        assertSame(jwt, first);
        assertSame(jwt, second);
        assertEquals(1, delegate.count(token("token1")));
    }

    @Test
    void reValidatesCachedJwtOnEveryDecode() {
        AtomicInteger validations = new AtomicInteger();
        OAuth2TokenValidator<Jwt> validator = validated -> {
            validations.incrementAndGet();
            return OAuth2TokenValidatorResult.success();
        };
        decoder(delegate(), validator);

        decoder.decode(token("token1"));
        decoder.decode(token("token1"));
        decoder.decode(token("token1"));

        // decoded (and validated) once via the delegate, the cache hits must still re-validate
        assertEquals(2, validations.get());
    }

    @Test
    void throwsAndEvictsWhenCachedJwtFailsRevalidation() {
        TestJwtDecoder delegate = delegate();
        decoder(delegate, alwaysInvalid());

        // first call goes straight to the delegate (which "already validates"), so it
        // is cached without going through validateJwt()
        decoder.decode(token("token1"));

        // second call is a cache hit and re-validates -> fails and evicts the entry
        assertThrows(JwtValidationException.class, () -> decoder.decode(token("token1")));

        // third decode should hit delegate again since the invalid entry was evicted
        decoder.decode(token("token1"));
        assertEquals(2, delegate.count(token("token1")));
    }

    @Test
    void propagatesDelegateExceptionsAndDoesNotCache() {
        TestJwtDecoder delegate = new TestJwtDecoder();
        delegate.answering(token -> {
            throw new JwtException("bad token");
        });
        decoder(delegate);

        assertThrows(JwtException.class, () -> decoder.decode(token("token1")));
        assertThrows(JwtException.class, () -> decoder.decode(token("token1")));
        assertEquals(2, delegate.count(token("token1")));
    }

    @Test
    void doesNotCacheTokenWhichIsNotJws() {
        TestJwtDecoder delegate = delegate();
        decoder(delegate);

        String noHeader = "not-a-jwt";
        String unparsableHeader = "xyz.abc.def";
        String unsecured = Base64URL.encode("{\"alg\":\"none\"}") + "." + Base64URL.encode("claims") + ".";
        for (String token : List.of(noHeader, unparsableHeader, unsecured)) {
            decoder.decode(token);
            decoder.decode(token);
            assertEquals(2, delegate.count(token), token);
        }
        assertEquals(0, decoder.getSize());
    }

    @Test
    void doesNotCacheJwtWithUnknownKeyId() {
        TestJwtDecoder delegate = delegate();
        decoder(delegate);

        decoder.decode(token("unknown-kid", "token1"));
        decoder.decode(token("unknown-kid", "token1"));

        // the JWK set has no key for the JWT -> never cached -> delegate invoked every time
        assertEquals(2, delegate.count(token("unknown-kid", "token1")));
        assertEquals(0, decoder.getSize());
    }

    @Test
    void doesNotRefreshJwkSetForUnknownKeyId() {
        decoder(delegate());

        decoder.decode(token("unknown-kid", "token1"));
        decoder.decode(token("unknown-kid", "token1"));

        // refreshing the JWK set for an unknown key is left to the delegate (i.e. its key selector, which is rate limited)
        assertEquals(0, jwkSetSource.getRefreshes());
    }

    @Test
    void cachesJwtWithoutKeyIdUntilAnyCandidateKeyChanges() {
        jwkSetSource.setJwkSet(jwkSet(key1, key2));
        TestJwtDecoder delegate = delegate();
        decoder(delegate);
        String token = token(null, "token1");

        decoder.decode(token);
        decoder.decode(token);
        assertEquals(1, delegate.count(token));

        // any of the keys might have verified the JWT
        jwkSetSource.setJwkSet(jwkSet(key1));
        decoder.decode(token);
        assertEquals(2, delegate.count(token));
    }

    // -----------------------------------------------------------------------
    // Following the JWK set
    // -----------------------------------------------------------------------

    @Test
    void keepsCachedJwtWhenJwkSetIsReloadedWithTheSameKeys() {
        TestJwtDecoder delegate = delegate();
        decoder(delegate);
        decoder.decode(token("token1"));

        // new key instances, same keys
        jwkSetSource.setJwkSet(jwkSet(key1));

        decoder.decode(token("token1"));
        assertEquals(1, delegate.count(token("token1")));
    }

    @Test
    void keepsCachedJwtWhenAnotherKeyIsAddedOrRemoved() {
        TestJwtDecoder delegate = delegate();
        decoder(delegate);
        decoder.decode(token("token1"));

        jwkSetSource.setJwkSet(jwkSet(key1, key2));
        decoder.decode(token("token1"));

        jwkSetSource.setJwkSet(jwkSet(key1));
        decoder.decode(token("token1"));

        assertEquals(1, delegate.count(token("token1")));
    }

    @Test
    void redecodesCachedJwtWhenItsKeyIsRemoved() {
        TestJwtDecoder delegate = delegate();
        decoder(delegate);
        decoder.decode(token("token1"));

        // i.e. revoked
        jwkSetSource.setJwkSet(jwkSet(key2));

        decoder.decode(token("token1"));
        assertEquals(2, delegate.count(token("token1")));
        assertEquals(0, decoder.getSize());
    }

    @Test
    void redecodesCachedJwtWhenItsKeyIsReplacedUnderTheSameKeyId() {
        TestJwtDecoder delegate = delegate();
        decoder(delegate);
        decoder.decode(token("token1"));

        jwkSetSource.setJwkSet(jwkSet(rotatedKey1));

        decoder.decode(token("token1"));
        assertEquals(2, delegate.count(token("token1")));

        // verified with (and so cached with) the new key
        decoder.decode(token("token1"));
        assertEquals(2, delegate.count(token("token1")));
    }

    @Test
    void redecodesCachedJwtWhenItsKeyMetadataChanges() {
        TestJwtDecoder delegate = delegate();
        decoder(delegate);
        decoder.decode(token("token1"));

        // same key material, but no longer the same JWK
        jwkSetSource.setJwkSet(new JWKSet(new ECKey.Builder(key1.toPublicJWK()).keyUse(KeyUse.SIGNATURE).build()));

        decoder.decode(token("token1"));
        assertEquals(2, delegate.count(token("token1")));
    }

    @Test
    void doesNotCacheJwtWhenJwkSetChangesWhileDecoding() {
        TestJwtDecoder delegate = new TestJwtDecoder();
        AtomicBoolean reload = new AtomicBoolean(true);
        delegate.answering(token -> {
            if (reload.getAndSet(false)) {
                // the JWK set is reloaded while decoding: the JWT might have been verified with the previous key
                jwkSetSource.setJwkSet(jwkSet(key1));
            }
            return jwt(token);
        });
        decoder(delegate);

        decoder.decode(token("token1"));
        assertEquals(0, decoder.getSize());

        decoder.decode(token("token1"));
        decoder.decode(token("token1"));
        assertEquals(2, delegate.count(token("token1")));
    }

    @Test
    void redecodesCachedJwtWhenJwkSetIsNotAvailable() {
        TestJwtDecoder delegate = delegate();
        decoder(delegate);
        decoder.decode(token("token1"));

        // i.e. the JWK set has expired and cannot be reloaded
        jwkSetSource.setFail(true);

        decoder.decode(token("token1"));
        assertEquals(2, delegate.count(token("token1")));
        assertEquals(0, decoder.getSize());

        jwkSetSource.setFail(false);
        decoder.decode(token("token1"));
        decoder.decode(token("token1"));
        assertEquals(3, delegate.count(token("token1")));
    }

    @Test
    void cachesWithOtherJwkSources() {
        jwkSource = new ImmutableJWKSet<>(jwkSet(key1));
        TestJwtDecoder delegate = delegate();
        decoder(delegate);

        decoder.decode(token("token1"));
        decoder.decode(token("token1"));
        assertEquals(1, delegate.count(token("token1")));
    }

    @Test
    void doesNotCacheWithJwkSourceWhichDoesNotCacheTheJwkSet() {
        // new key instances on every call
        jwkSource = (selector, context) -> selector.select(jwkSet(key1));
        TestJwtDecoder delegate = delegate();
        decoder(delegate);

        decoder.decode(token("token1"));
        decoder.decode(token("token1"));
        assertEquals(2, delegate.count(token("token1")));
    }

    // -----------------------------------------------------------------------
    // maxCacheSize enforcement
    // -----------------------------------------------------------------------

    @Test
    void neverCachesMoreThanMaxCacheSize() {
        int maxCacheSize = 5;
        int distinctTokens = 50;

        decoder = new DecodedJwtCacheJwtDecoder(delegate(), jwkSource, alwaysValid(), CLEANUP_INTERVAL, maxCacheSize, JwtDecoderCacheMode.FIXED);

        for (int i = 0; i < distinctTokens; i++) {
            decoder.decode(token("token-" + i));
            assertTrue(decoder.getSize() <= maxCacheSize,
                    "cache size " + decoder.getSize() + " must never exceed maxCacheSize " + maxCacheSize);
        }

        assertEquals(maxCacheSize, decoder.getSize(), "cache should have filled up to the configured limit");
    }

    @Test
    void stopsCachingNewEntriesOnceMaxCacheSizeIsReachedButKeepsServingCachedOnes() {
        int maxCacheSize = 2;

        TestJwtDecoder delegate = delegate();
        decoder = new DecodedJwtCacheJwtDecoder(delegate, jwkSource, alwaysValid(), CLEANUP_INTERVAL, maxCacheSize, JwtDecoderCacheMode.FIXED);

        // fill the cache to its limit
        decoder.decode(token("token-0"));
        decoder.decode(token("token-1"));
        assertEquals(maxCacheSize, decoder.getSize());

        // already-cached entries are still served from cache
        decoder.decode(token("token-0"));
        decoder.decode(token("token-1"));
        assertEquals(1, delegate.count(token("token-0")));
        assertEquals(1, delegate.count(token("token-1")));

        // cache is full -> new entries are not added, delegate is invoked every time
        decoder.decode(token("token-2"));
        decoder.decode(token("token-2"));
        assertEquals(maxCacheSize, decoder.getSize());
        assertEquals(2, delegate.count(token("token-2")));
    }

    @Test
    void unboundedCacheSizeAllowsGrowthBeyondDefault() {
        int distinctTokens = 500;

        // -1 disables the cap (translated internally to Integer.MAX_VALUE)
        decoder = new DecodedJwtCacheJwtDecoder(delegate(), jwkSource, alwaysValid(), CLEANUP_INTERVAL, -1);

        for (int i = 0; i < distinctTokens; i++) {
            decoder.decode(token("token-" + i));
        }

        assertEquals(distinctTokens, decoder.getSize());
    }

    @Test
    void testLargeMaxCacheSizeDoesNotOverflowOrPreallocate() {
        // 2 * Integer.MAX_VALUE overflows an int; must neither throw nor allocate a huge table
        decoder = new DecodedJwtCacheJwtDecoder(delegate(), jwkSource, alwaysValid(), CLEANUP_INTERVAL, Integer.MAX_VALUE);

        decoder.decode(token("token1"));
        assertEquals(1, decoder.getSize());
    }

    // -----------------------------------------------------------------------
    // clear()
    // -----------------------------------------------------------------------

    @Test
    void clearRemovesCachedEntries() {
        TestJwtDecoder delegate = delegate();
        decoder(delegate);

        decoder.decode(token("token1"));
        decoder.clear();
        decoder.decode(token("token1"));

        assertEquals(2, delegate.count(token("token1")));
    }

    // -----------------------------------------------------------------------
    // cleanup()
    // -----------------------------------------------------------------------

    @Test
    void cleanupDoesNothingWhenCacheIsEmpty() {
        AtomicInteger validations = new AtomicInteger();
        OAuth2TokenValidator<Jwt> validator = validated -> {
            validations.incrementAndGet();
            return OAuth2TokenValidatorResult.success();
        };
        decoder(delegate(), validator);

        decoder.cleanup();

        // nothing cached -> validator should never be invoked by cleanup
        assertEquals(0, validations.get());
        assertEquals(0, decoder.getSize());
    }

    @Test
    void cleanupRemovesInvalidJwtsFromCache() {
        TestJwtDecoder delegate = delegate();
        decoder(delegate, alwaysInvalid());

        // cached without going through validateJwt(), since the delegate already validates it
        decoder.decode(token("token1"));
        assertEquals(1, decoder.getSize());

        decoder.cleanup();

        // the invalid entry should have been evicted by cleanup()
        assertEquals(0, decoder.getSize());

        // subsequent decode must hit the delegate again since the cache entry is gone
        decoder.decode(token("token1"));
        assertEquals(2, delegate.count(token("token1")));
    }

    @Test
    void cleanupKeepsStillValidJwtsInCache() {
        TestJwtDecoder delegate = delegate();
        decoder(delegate);

        decoder.decode(token("token1"));
        assertEquals(1, decoder.getSize());

        decoder.cleanup();

        // still valid -> not evicted
        assertEquals(1, decoder.getSize());
        decoder.decode(token("token1"));
        assertEquals(1, delegate.count(token("token1")));
    }

    @Test
    void cleanupSwallowsExceptionsThrownByValidator() {
        // decode() itself is not affected by the validator since the delegate "already validates",
        // so the first call just caches the entry
        OAuth2TokenValidator<Jwt> validator = validated -> {
            throw new RuntimeException("TEST EXCEPTION");
        };
        decoder(delegate(), validator);

        decoder.decode(token("token1"));
        assertEquals(1, decoder.getSize());

        // cleanup() must not propagate exceptions raised while revalidating cached entries
        assertDoesNotThrow(() -> decoder.cleanup());
    }

    @Test
    void scheduleCleanupPeriodicallyEvictsInvalidJwts() throws Exception {
        long shortCleanupInterval = 20L;
        decoder = new DecodedJwtCacheJwtDecoder(delegate(), jwkSource, alwaysInvalid(), shortCleanupInterval, MAX_TOKENS);

        decoder.decode(token("token1"));
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
        decoder = new DecodedJwtCacheJwtDecoder(delegate(), jwkSource, alwaysValid(), 0L, MAX_TOKENS);

        // must not throw and must not schedule anything against the executor
        assertFalse(assertDoesNotThrow(() -> decoder.scheduleCleanup()));
        assertNull(decoder.scheduledExecutorService);
    }

    @Test
    void scheduleCleanupIsIdempotent() {
        decoder(delegate());

        assertTrue(decoder.scheduleCleanup());
        java.util.concurrent.ScheduledFuture<?> task = decoder.cleanupTask;
        assertNotNull(task);

        // a single periodic task; the second call must not replace (or add to) the first
        assertFalse(decoder.scheduleCleanup());
        assertSame(task, decoder.cleanupTask);
        assertFalse(task.isDone());
    }

    @Test
    void cleanupThreadIsNamedAfterDecoder() throws Exception {
        decoder = new DecodedJwtCacheJwtDecoder("https://issuer.a", delegate(), jwkSource, alwaysValid(), CLEANUP_INTERVAL, MAX_TOKENS, JwtDecoderCacheMode.LRU);
        assertEquals("https://issuer.a", decoder.getName());

        Thread thread = decoder.getScheduledExecutorService().submit(Thread::currentThread).get(5, TimeUnit.SECONDS);
        assertTrue(thread.isDaemon());
        assertEquals("decoded-jwt-cache-cleanup-https://issuer.a", thread.getName());
    }

    // -----------------------------------------------------------------------
    // Concurrency
    // -----------------------------------------------------------------------

    @Test
    void concurrentDecodeAndKeyRotationOnlyCachesJwtsWithTheKeysTheyWereVerifiedWith() throws Exception {
        // like a real decoder: verifies with the key currently in the JWK set
        TestJwtDecoder delegate = new TestJwtDecoder().answering(token -> {
            JWK key = jwkSetSource.getJwkSet().getKeyByKeyId("kid1");
            return Jwt.withTokenValue(token)
                    .header("alg", "ES256")
                    .header("verified-with", thumbprint(key))
                    .claim("sub", "user")
                    .build();
        });
        decoder(delegate);

        int rotatorThreads = 1;
        int decoderThreads = Math.min(8, Math.max(1, Runtime.getRuntime().availableProcessors() - rotatorThreads));
        int iterationsPerDecoderThread = 50000;

        ExecutorService executor = Executors.newFixedThreadPool(decoderThreads + rotatorThreads);
        try {
            CountDownLatch start = new CountDownLatch(1);
            AtomicInteger errors = new AtomicInteger();
            AtomicBoolean rotating = new AtomicBoolean(true);

            List<Future<?>> futures = new ArrayList<>();
            for (int t = 0; t < decoderThreads; t++) {
                final int threadIndex = t;
                futures.add(executor.submit(() -> {
                    try {
                        start.await();
                        for (int i = 0; i < iterationsPerDecoderThread && rotating.get(); i++) {
                            try {
                                decoder.decode(token("token-" + threadIndex + "-" + (i % 10)));
                            } catch (RuntimeException e) {
                                errors.incrementAndGet();
                            }
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }));
            }

            futures.add(executor.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < 2000; i++) {
                        // alternate between the two keys, always as new instances
                        jwkSetSource.setJwkSet(i % 2 == 0 ? jwkSet(rotatedKey1) : jwkSet(key1));
                        if (i % 100 == 0) {
                            Thread.sleep(1);
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    rotating.set(false);
                }
            }));

            start.countDown();

            for (Future<?> future : futures) {
                future.get(60, TimeUnit.SECONDS);
            }

            assertEquals(0, errors.get(), "decode() should never throw under concurrent key rotation");
        } finally {
            executor.shutdownNow();
        }

        // every cached JWT holds the key which verified it, so that it is redecoded once the key is gone
        for (DecodedJwtCacheJwtDecoder.Entry entry : decoder.cache.map.values()) {
            Object verifiedWith = entry.jwt.getHeaders().get("verified-with");
            assertTrue(entry.keys.stream().anyMatch(key -> thumbprint(key).equals(verifiedWith)), entry.jwt.getTokenValue());
        }
    }

    private static String thumbprint(JWK key) {
        try {
            return key.computeThumbprint().toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    @Test
    void testConstructorRejectsMaxCacheSizeLessThanNegativeOne() {
        TestJwtDecoder delegate = delegate();
        OAuth2TokenValidator<Jwt> validator = alwaysValid();

        assertThrows(IllegalArgumentException.class, () -> new DecodedJwtCacheJwtDecoder(delegate, jwkSource, validator, CLEANUP_INTERVAL, -2));
    }

    @Test
    void testConstructorRejectsMissingJwkSource() {
        TestJwtDecoder delegate = delegate();
        OAuth2TokenValidator<Jwt> validator = alwaysValid();

        assertThrows(IllegalArgumentException.class, () -> new DecodedJwtCacheJwtDecoder(delegate, null, validator, CLEANUP_INTERVAL, MAX_TOKENS));
    }

    @Test
    void testDefaultScheduledExecutorServiceUsesNamedDaemonThread() throws Exception {
        java.util.concurrent.ScheduledExecutorService executor = DecodedJwtCacheJwtDecoder.createDefaultScheduledExecutorService();
        try {
            Thread thread = executor.submit(Thread::currentThread).get(5, TimeUnit.SECONDS);
            assertTrue(thread.isDaemon());
            assertEquals("decoded-jwt-cache-cleanup", thread.getName());
        } finally {
            executor.shutdownNow();
        }
    }
}
