package org.entur.jwt.spring.decode.cache;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import org.entur.jwt.spring.properties.jwk.JwtDecoderCacheMode;
import org.entur.jwt.spring.properties.jwk.JwtDecoderCacheProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DecodedJwtCacheModeTest {

    private static final long CLEANUP_INTERVAL = 0; // disabled

    private final AtomicInteger decodes = new AtomicInteger();

    private final JwtDecoder delegate = token -> {
        decodes.incrementAndGet();
        return Jwt.withTokenValue(token)
                .header("kid", "kid1")
                .header("alg", "none")
                .claim("sub", token)
                .build();
    };

    private DecodedJwtCacheJwtDecoder decoder;

    private DecodedJwtCacheJwkEventListener jwkEventListener;

    // the JWK event listener for the current decoder
    private DecodedJwtCacheJwkEventListener jwkEventListener() {
        DecodedJwtCacheJwkEventListener l = jwkEventListener;
        if (l == null || l.getDecoder() != decoder) {
            l = new DecodedJwtCacheJwkEventListener(decoder);
            jwkEventListener = l;
        }
        return l;
    }
    private ListAppender<ILoggingEvent> logAppender;

    @BeforeEach
    void setUpLogCapture() {
        logAppender = new ListAppender<>();
        logAppender.start();
        ((Logger) LoggerFactory.getLogger(DecodedJwtCacheJwtDecoder.class)).addAppender(logAppender);
    }

    @AfterEach
    void tearDown() {
        ((Logger) LoggerFactory.getLogger(DecodedJwtCacheJwtDecoder.class)).detachAppender(logAppender);
        if (decoder != null) {
            decoder.close();
        }
    }

    private DecodedJwtCacheJwtDecoder decoder(int maxSize, JwtDecoderCacheMode mode) {
        decoder = new DecodedJwtCacheJwtDecoder(delegate, jwt -> OAuth2TokenValidatorResult.success(), CLEANUP_INTERVAL, maxSize, mode);
        jwkEventListener().notify(refreshCompletedEvent());
        return decoder;
    }

    @SuppressWarnings("unchecked")
    private static CachingJWKSetSource.RefreshCompletedEvent<?> refreshCompletedEvent() {
        CachingJWKSetSource.RefreshCompletedEvent<?> event = mock(CachingJWKSetSource.RefreshCompletedEvent.class);
        JWKSet jwkSet = new JWKSet(new OctetSequenceKey.Builder("secret-material".getBytes()).keyID("kid1").build());
        when(event.getJWKSet()).thenReturn(jwkSet);
        return event;
    }

    private void fill(int count) {
        for (int i = 0; i < count; i++) {
            decoder.decode("token" + i);
        }
    }

    private void awaitSize(int size) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 10_000;
        while (decoder.getSize() != size) {
            if (System.currentTimeMillis() > deadline) {
                throw new AssertionError("Expected size " + size + ", was " + decoder.getSize());
            }
            Thread.sleep(1);
        }
    }

    private boolean isCached(String token) {
        return decoder.cache.map.containsKey(token);
    }

    @Test
    void testFixedDoesNotCacheNewJwtsWhenFullAndWarnsOnce() {
        decoder(10, JwtDecoderCacheMode.FIXED);
        fill(10);

        decoder.decode("new1");
        decoder.decode("new2");

        assertEquals(10, decoder.getSize());
        assertFalse(isCached("new1"));
        assertTrue(isCached("token0"));
        assertEquals(1, logAppender.list.stream().filter(e -> e.getFormattedMessage().startsWith("Decoded JWT cache is full")).count());
    }

    @Test
    void testFifoEvictsFirstCachedJwtsEvenIfRecentlyUsed() throws Exception {
        decoder(10, JwtDecoderCacheMode.FIFO);
        fill(10);

        decoder.decode("token0"); // cache hit, does not affect FIFO order
        decoder.decode("new");

        // max size temporarily exceeded, then evicted down to 90%
        awaitSize(9);
        assertTrue(isCached("new"));
        assertFalse(isCached("token0"));
        assertFalse(isCached("token1"));
        assertTrue(isCached("token2"));
    }

    @Test
    void testLruEvictsLeastRecentlyUsedJwts() throws Exception {
        decoder(10, JwtDecoderCacheMode.LRU);
        fill(10);

        // deterministic access times, one second apart; token0 is the least recently used
        long now = System.currentTimeMillis();
        for (int i = 0; i < 10; i++) {
            decoder.cache.map.get("token" + i).accessed = now - (10 - i) * 1000L;
        }
        decoder.decode("token0"); // cache hit, now the most recently used

        decoder.decode("new");

        awaitSize(9);
        assertTrue(isCached("new"));
        assertTrue(isCached("token0"));
        assertFalse(isCached("token1"));
        assertFalse(isCached("token2"));
        assertTrue(isCached("token3"));
    }

    @Test
    void testCacheHitDoesNotDecode() {
        decoder(10, JwtDecoderCacheMode.LRU);
        decoder.decode("token");
        decoder.decode("token");
        decoder.decode("token");

        assertEquals(1, decodes.get());
    }

    @Test
    void testEvictsDownToNinetyPercentInBackground() throws Exception {
        decoder(100, JwtDecoderCacheMode.FIFO);
        fill(100);

        decoder.decode("new");

        awaitSize(90);
        for (int i = 0; i < 11; i++) {
            assertFalse(isCached("token" + i));
        }
        assertTrue(isCached("token11"));
        assertTrue(isCached("new"));
    }

    @Test
    void testDoesNotCacheBeyondTwiceMaxSizeWhenEvictionDoesNotKeepUp() {
        decoder(10, JwtDecoderCacheMode.LRU);
        decoder.cache.evictionScheduled.set(true); // simulate eviction not running
        fill(30);

        assertEquals(20, decoder.getSize());
        assertEquals(1, logAppender.list.stream().filter(e -> e.getFormattedMessage().startsWith("Decoded JWT cache eviction does not keep up")).count());
    }

    @Test
    void testNoEvictionAfterClose() {
        decoder(10, JwtDecoderCacheMode.LRU);
        fill(10);
        decoder.close();

        decoder.decode("new");

        assertEquals(11, decoder.getSize());
    }

    @Test
    void testMaxSizeZeroCachesNothing() {
        decoder(0, JwtDecoderCacheMode.LRU);
        fill(3);
        assertEquals(0, decoder.getSize());
    }

    @Test
    void testFifoOrderSurvivesKeyRefresh() throws Exception {
        decoder(10, JwtDecoderCacheMode.FIFO);
        fill(10);

        // new key added, existing kid unchanged, so the JWTs are migrated to a new cache
        CachingJWKSetSource.RefreshCompletedEvent<?> event = mock(CachingJWKSetSource.RefreshCompletedEvent.class);
        JWKSet jwkSet = new JWKSet(List.of(
                new OctetSequenceKey.Builder("secret-material".getBytes()).keyID("kid1").build(),
                new OctetSequenceKey.Builder("other-material".getBytes()).keyID("kid2").build()));
        when(event.getJWKSet()).thenReturn((JWKSet) jwkSet);
        jwkEventListener().notify(event);
        assertEquals(10, decoder.getSize());

        decoder.decode("new");

        awaitSize(9);
        assertTrue(isCached("new"));
        assertFalse(isCached("token0"));
        assertTrue(isCached("token2"));
    }

    @Test
    void testConcurrentAddsStayCloseToMaxSize() throws Exception {
        int maxSize = 50;
        int threads = 8;
        decoder(maxSize, JwtDecoderCacheMode.LRU);

        ExecutorService executor = Executors.newFixedThreadPool(threads);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                int thread = t;
                futures.add(executor.submit(() -> {
                    for (int i = 0; i < 5_000; i++) {
                        decoder.decode("t" + thread + "-" + i);
                        decoder.decode("t" + thread + "-" + (i / 2));
                        // hard max (2 * max size) is approximate: the size check is not atomic with the put
                        assertTrue(decoder.getSize() <= 3 * maxSize);
                    }
                }));
            }
            for (Future<?> future : futures) {
                future.get(60, TimeUnit.SECONDS);
            }
        } finally {
            executor.shutdownNow();
        }
        long deadline = System.currentTimeMillis() + 10_000;
        while (decoder.getSize() > maxSize && System.currentTimeMillis() < deadline) {
            Thread.sleep(1);
        }
        assertTrue(decoder.getSize() <= maxSize);
    }

    private static DecodedJwtCacheJwtDecoder.Cache cacheWithOrders(long... sequences) {
        DecodedJwtCacheJwtDecoder.Cache cache = new DecodedJwtCacheJwtDecoder.Cache(DecodedJwtCacheJWKRepresentations.empty(), 1000, JwtDecoderCacheMode.FIFO, jwt -> OAuth2TokenValidatorResult.success(), Runnable::run);
        for (int i = 0; i < sequences.length; i++) {
            Jwt jwt = Jwt.withTokenValue("t" + i).header("alg", "none").claim("sub", "s").build();
            cache.map.put("t" + i, new DecodedJwtCacheJwtDecoder.Entry(jwt, sequences[i], 0));
        }
        return cache;
    }

    @Test
    void testEvictRemovesLowestOrdersByHistogram() {
        java.util.Random random = new java.util.Random(1);
        for (int run = 0; run < 200; run++) {
            int n = 1 + random.nextInt(500);
            long[] sequences = new long[n];
            for (int i = 0; i < n; i++) {
                sequences[i] = random.nextInt(1_000_000);
            }
            DecodedJwtCacheJwtDecoder.Cache cache = cacheWithOrders(sequences);
            int count = random.nextInt(n + 1);

            long min = java.util.Arrays.stream(sequences).min().getAsLong();
            long max = java.util.Arrays.stream(sequences).max().getAsLong();
            int buckets = Math.min(n, DecodedJwtCacheJwtDecoder.Cache.HISTOGRAM_BUCKETS);
            long width = (max - min) / buckets + 1;

            cache.evict(count);

            assertEquals(n - count, cache.size());

            // everything kept is in the same or a higher bucket than everything evicted
            java.util.Set<String> kept = cache.map.keySet();
            int maxEvictedBucket = -1;
            int minKeptBucket = Integer.MAX_VALUE;
            for (int i = 0; i < n; i++) {
                int bucket = DecodedJwtCacheJwtDecoder.Cache.bucket(sequences[i], min, width, buckets);
                if (kept.contains("t" + i)) {
                    minKeptBucket = Math.min(minKeptBucket, bucket);
                } else {
                    maxEvictedBucket = Math.max(maxEvictedBucket, bucket);
                }
            }
            assertTrue(maxEvictedBucket <= minKeptBucket);
        }
    }

    @Test
    void testEvictTooFullBucketTakesWhicheverFirst() {
        // skewed: an outlier puts all other entries in the first bucket
        DecodedJwtCacheJwtDecoder.Cache cache = cacheWithOrders(1, 2, 3, 4, 5, 6, 7, 8, 9, 1_000_000);

        cache.evict(3);

        assertEquals(7, cache.size());
        assertTrue(cache.map.containsKey("t9"));
    }

    @Test
    void testRejectsNullMode() {
        assertThrows(IllegalArgumentException.class, () -> new DecodedJwtCacheJwtDecoder(delegate, jwt -> OAuth2TokenValidatorResult.success(), CLEANUP_INTERVAL, 10, null));
        assertThrows(IllegalArgumentException.class, () -> new JwtDecoderCacheProperties().setMode(null));
    }

    @Test
    void testDefaultModeIsLru() {
        assertEquals(JwtDecoderCacheMode.LRU, new JwtDecoderCacheProperties().getMode());
    }
}
