package org.entur.jwt.spring.decode.cache;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.jwk.source.RefreshAheadCachingJWKSetSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.entur.jwt.spring.actuate.ListEventListener;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.util.Date;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the decoded JWT cache against JWK sources built by {@link JWKSourceBuilder}, i.e. with the events
 * a real JWK source chain actually fires.
 */
class DecodedJwtCacheJwtDecoderJwkSourceTest {

    private static final long JWK_CACHE_TIME_TO_LIVE = 1500;
    private static final long JWK_CACHE_REFRESH_TIMEOUT = 200;
    // scheduled refresh-ahead runs 1500 - 500 - 200 = 800 ms after each JWK set load
    private static final long JWK_CACHE_REFRESH_AHEAD = 500;

    private static RSAKey key;

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

    @BeforeAll
    static void createKey() throws Exception {
        key = new RSAKeyGenerator(2048).keyID("k1").generate();
    }

    @AfterEach
    void tearDown() {
        if (decoder != null) {
            decoder.close();
        }
    }

    private static String token(RSAKey key, String subject) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(subject)
                .expirationTime(new Date(System.currentTimeMillis() + 3_600_000))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private static NimbusJwtDecoder nimbusJwtDecoder(JWKSource<SecurityContext> jwkSource) {
        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.Family.SIGNATURE, jwkSource));
        NimbusJwtDecoder nimbusJwtDecoder = new NimbusJwtDecoder(jwtProcessor);
        nimbusJwtDecoder.setJwtValidator(jwt -> OAuth2TokenValidatorResult.success());
        return nimbusJwtDecoder;
    }

    private static JWKSource<SecurityContext> jwkSource(JWKSetSource<SecurityContext> source, ListEventListener listener, long outageCacheTimeToLive) {
        // similar to JwkSourceMapFactory, with eager (scheduled) refresh-ahead
        JWKSourceBuilder<SecurityContext> builder = JWKSourceBuilder.create(source)
                .rateLimited(false)
                .cache(JWK_CACHE_TIME_TO_LIVE, JWK_CACHE_REFRESH_TIMEOUT, listener)
                .refreshAheadCache(JWK_CACHE_REFRESH_AHEAD, true, listener)
                .retrying(listener);
        if (outageCacheTimeToLive > 0) {
            builder.outageTolerant(outageCacheTimeToLive, listener);
        } else {
            builder.outageTolerant(false);
        }
        return builder.build();
    }

    private static void await(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 10_000;
        while (!condition.getAsBoolean()) {
            if (System.currentTimeMillis() > deadline) {
                throw new AssertionError("Timeout waiting for condition");
            }
            Thread.sleep(10);
        }
    }

    @Test
    void testCacheIsUsedUntilJwkOutageCacheExpires() throws Exception {
        TestJWKSetSource source = new TestJWKSetSource(new JWKSet(key.toPublicJWK()));
        ListEventListener listener = new ListEventListener();
        long outageCacheTimeToLive = 3000;
        JWKSource<SecurityContext> jwkSource = jwkSource(source, listener, outageCacheTimeToLive);

        AtomicInteger decodes = new AtomicInteger();
        NimbusJwtDecoder nimbusJwtDecoder = nimbusJwtDecoder(jwkSource);
        decoder = new DecodedJwtCacheJwtDecoder(t -> {
            decodes.incrementAndGet();
            return nimbusJwtDecoder.decode(t);
        }, jwt -> OAuth2TokenValidatorResult.success(), 0, 100);
        listener.addEventListener(jwkEventListener());

        String token = token(key, "a");
        decoder.decode(token); // loads the JWK set, not cached since the keys changed during decode
        long loadedAt = System.currentTimeMillis();
        decoder.decode(token);
        assertEquals(2, decodes.get());
        assertEquals(1, decoder.getSize());

        // the JWK outage cache masks the failure as a completed refresh, but also fires an OutageEvent
        source.setFail(true);
        await(() -> decoder.suspendedAt != DecodedJwtCacheJwtDecoder.NEVER);

        // while the JWK outage cache is valid, the cache is used
        decoder.decode(token);
        assertEquals(2, decodes.get());

        Thread.sleep(Math.max(0, loadedAt + outageCacheTimeToLive + 100 - System.currentTimeMillis()));

        // JWK outage cache expired: decoded as if not cached
        decoder.decode(token);
        decoder.decode(token);
        assertEquals(4, decodes.get());
        assertEquals(0, decoder.getSize());
    }

    @Test
    void testCacheIsNotUsedAfterFailedRefreshWithoutJwkOutageCache() throws Exception {
        TestJWKSetSource source = new TestJWKSetSource(new JWKSet(key.toPublicJWK()));
        List<Object> events = new CopyOnWriteArrayList<>();
        ListEventListener listener = new ListEventListener();
        listener.addEventListener(events::add);
        JWKSource<SecurityContext> jwkSource = jwkSource(source, listener, 0);

        decoder = new DecodedJwtCacheJwtDecoder(nimbusJwtDecoder(jwkSource), jwt -> OAuth2TokenValidatorResult.success(), 0, 100);
        listener.addEventListener(jwkEventListener());

        String token = token(key, "a");
        decoder.decode(token);
        decoder.decode(token);
        assertEquals(1, decoder.getSize());

        source.setFail(true);

        // the scheduled refresh-ahead fails (once, it is not rescheduled)
        await(() -> events.stream().anyMatch(e -> e instanceof RefreshAheadCachingJWKSetSource.UnableToRefreshAheadOfExpirationEvent));

        // decoded as if not cached; the JWK set is still cached by the JWK source for a while
        decoder.decode(token);
        assertEquals(0, decoder.getSize());

        // once the JWK source cache expires, the JWT is rejected
        Thread.sleep(JWK_CACHE_TIME_TO_LIVE);
        assertThrows(JwtException.class, () -> decoder.decode(token));

        // recovery: successful refresh resumes caching
        source.setFail(false);
        decoder.decode(token);
        decoder.decode(token);
        assertEquals(1, decoder.getSize());
    }

    @Test
    void testJwtVerifiedWithReplacedKeyIsNotCachedWhenRefreshCompletesDuringDecode() throws Exception {
        RSAKey oldKey = new RSAKeyGenerator(2048).keyID("a").generate();
        RSAKey newKey = new RSAKeyGenerator(2048).keyID("a").generate(); // same kid, different key

        JWKSet oldJwkSet = new JWKSet(oldKey.toPublicJWK());
        JWKSet newJwkSet = new JWKSet(newKey.toPublicJWK());

        AtomicBoolean rotated = new AtomicBoolean();
        NimbusJwtDecoder nimbusJwtDecoder = nimbusJwtDecoder((selector, context) -> selector.select(rotated.get() ? newJwkSet : oldJwkSet));

        // the JWK set refresh completes after the JWT was verified with the old key, but before it is cached
        AtomicBoolean rotateDuringDecode = new AtomicBoolean(true);
        JwtDecoder delegate = token -> {
            Jwt jwt = nimbusJwtDecoder.decode(token);
            if (rotateDuringDecode.getAndSet(false)) {
                rotated.set(true);
                JwkEvents.refresh(jwkEventListener(), newJwkSet);
            }
            return jwt;
        };

        decoder = new DecodedJwtCacheJwtDecoder(delegate, jwt -> OAuth2TokenValidatorResult.success(), 0, 100);
        JwkEvents.refresh(jwkEventListener(), oldJwkSet);

        String token = token(oldKey, "a");
        decoder.decode(token);

        assertEquals(0, decoder.getSize());
        assertThrows(JwtException.class, () -> decoder.decode(token));
    }
}
