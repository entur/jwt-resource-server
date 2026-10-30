package org.entur.jwt.spring.decode.cache;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
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

/**
 * Tests the decoded JWT cache against JWK sources built by {@link JWKSourceBuilder}, i.e. a real JWK source chain
 * with caching, refresh-ahead and outage tolerance, and JWTs verified by a {@link NimbusJwtDecoder}.
 */
class DecodedJwtCacheJwtDecoderJwkSourceTest {

    private static final long JWK_CACHE_TIME_TO_LIVE = 1500;
    private static final long JWK_CACHE_REFRESH_TIMEOUT = 200;
    // scheduled refresh-ahead runs 1500 - 500 - 200 = 800 ms after each JWK set load
    private static final long JWK_CACHE_REFRESH_AHEAD = 500;

    private static RSAKey key;

    private DecodedJwtCacheJwtDecoder decoder;

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

    // counts the decodes by the (verifying) delegate decoder
    private DecodedJwtCacheJwtDecoder decoder(JWKSource<SecurityContext> jwkSource, AtomicInteger decodes) {
        NimbusJwtDecoder nimbusJwtDecoder = nimbusJwtDecoder(jwkSource);
        decoder = new DecodedJwtCacheJwtDecoder(t -> {
            decodes.incrementAndGet();
            return nimbusJwtDecoder.decode(t);
        }, jwkSource, jwt -> OAuth2TokenValidatorResult.success(), 0, 100);
        return decoder;
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

    private static boolean isAvailable(JWKSource<SecurityContext> jwkSource) {
        try {
            jwkSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
            return true;
        } catch (KeySourceException e) {
            return false;
        }
    }

    private static void sleepUntil(long time) throws InterruptedException {
        Thread.sleep(Math.max(0, time - System.currentTimeMillis()));
    }

    @Test
    void testCacheIsUsedWhileJwkSetIsServedFromJwkOutageCache() throws Exception {
        TestJWKSetSource source = new TestJWKSetSource(new JWKSet(key.toPublicJWK()));
        long outageCacheTimeToLive = 3000;
        JWKSource<SecurityContext> jwkSource = jwkSource(source, new ListEventListener(), outageCacheTimeToLive);

        AtomicInteger decodes = new AtomicInteger();
        decoder(jwkSource, decodes);

        String token = token(key, "a");
        decoder.decode(token); // loads the JWK set
        long loadedAt = System.currentTimeMillis();
        decoder.decode(token);
        assertEquals(1, decodes.get());
        assertEquals(1, decoder.getSize());

        // outage: the JWK set expires, but is served from the JWK outage cache, so is the cached JWT
        source.setFail(true);
        sleepUntil(loadedAt + JWK_CACHE_TIME_TO_LIVE + 200);
        decoder.decode(token);
        assertEquals(1, decodes.get());

        // the JWK outage cache expires: once the JWK source no longer serves the JWK set, the JWT is rejected
        sleepUntil(loadedAt + outageCacheTimeToLive);
        await(() -> !isAvailable(jwkSource));
        assertThrows(JwtException.class, () -> decoder.decode(token));
        assertEquals(0, decoder.getSize());
    }

    @Test
    void testCachedJwtIsRejectedOnceJwkSetExpiresWithoutJwkOutageCache() throws Exception {
        TestJWKSetSource source = new TestJWKSetSource(new JWKSet(key.toPublicJWK()));
        List<Object> events = new CopyOnWriteArrayList<>();
        ListEventListener listener = new ListEventListener();
        listener.addEventListener(events::add);
        JWKSource<SecurityContext> jwkSource = jwkSource(source, listener, 0);

        AtomicInteger decodes = new AtomicInteger();
        decoder(jwkSource, decodes);

        String token = token(key, "a");
        decoder.decode(token);
        long loadedAt = System.currentTimeMillis();
        decoder.decode(token);
        assertEquals(1, decoder.getSize());

        source.setFail(true);

        // the scheduled refresh-ahead fails, but the JWK set is still cached by the JWK source for a while
        await(() -> events.stream().anyMatch(e -> e instanceof RefreshAheadCachingJWKSetSource.UnableToRefreshAheadOfExpirationEvent));
        decoder.decode(token);
        assertEquals(1, decodes.get());

        // once the JWK source cache expires, the JWT is rejected
        sleepUntil(loadedAt + JWK_CACHE_TIME_TO_LIVE + 200);
        assertThrows(JwtException.class, () -> decoder.decode(token));
        assertEquals(0, decoder.getSize());

        // recovery: the JWT is verified and cached again
        source.setFail(false);
        decoder.decode(token);
        decoder.decode(token);
        assertEquals(1, decoder.getSize());
    }

    @Test
    void testJwtVerifiedWithReplacedKeyIsNotCachedWhenJwkSetChangesDuringDecode() throws Exception {
        RSAKey oldKey = new RSAKeyGenerator(2048).keyID("a").generate();
        RSAKey newKey = new RSAKeyGenerator(2048).keyID("a").generate(); // same kid, different key

        JWKSet oldJwkSet = new JWKSet(oldKey.toPublicJWK());
        JWKSet newJwkSet = new JWKSet(newKey.toPublicJWK());

        AtomicBoolean rotated = new AtomicBoolean();
        JWKSource<SecurityContext> jwkSource = (selector, context) -> selector.select(rotated.get() ? newJwkSet : oldJwkSet);
        NimbusJwtDecoder nimbusJwtDecoder = nimbusJwtDecoder(jwkSource);

        // the JWK set is reloaded after the JWT was verified with the old key, but before it is cached
        AtomicBoolean rotateDuringDecode = new AtomicBoolean(true);
        JwtDecoder delegate = token -> {
            Jwt jwt = nimbusJwtDecoder.decode(token);
            if (rotateDuringDecode.getAndSet(false)) {
                rotated.set(true);
            }
            return jwt;
        };

        decoder = new DecodedJwtCacheJwtDecoder(delegate, jwkSource, jwt -> OAuth2TokenValidatorResult.success(), 0, 100);

        String token = token(oldKey, "a");
        decoder.decode(token);

        assertEquals(0, decoder.getSize());
        assertThrows(JwtException.class, () -> decoder.decode(token));
    }

    @Test
    void testKeyRotationIsDetectedOnceJwkSetIsRefreshed() throws Exception {
        RSAKey rotatedKey = new RSAKeyGenerator(2048).keyID("k2").generate();

        TestJWKSetSource source = new TestJWKSetSource(new JWKSet(key.toPublicJWK()));
        List<Object> events = new CopyOnWriteArrayList<>();
        ListEventListener listener = new ListEventListener();
        listener.addEventListener(events::add);
        JWKSource<SecurityContext> jwkSource = jwkSource(source, listener, 0);

        AtomicInteger decodes = new AtomicInteger();
        decoder(jwkSource, decodes);

        String token = token(key, "a");
        decoder.decode(token);
        decoder.decode(token);
        assertEquals(1, decoder.getSize());

        // the authorization server rotates its key: only the new key is published
        source.setJwkSet(new JWKSet(rotatedKey.toPublicJWK()));

        // the scheduled (eager) refresh-ahead picks up the new JWK set
        await(() -> events.stream().anyMatch(e -> e instanceof RefreshAheadCachingJWKSetSource.ScheduledRefreshCompletedEvent));

        // the JWT signed with the rotated-away key is no longer accepted
        assertThrows(JwtException.class, () -> decoder.decode(token));
        assertEquals(0, decoder.getSize());

        // JWTs signed with the new key are verified and cached
        String rotatedToken = token(rotatedKey, "b");
        decoder.decode(rotatedToken);
        assertEquals(1, decoder.getSize());
    }

    @Test
    void testTamperedJwtIsNotServedFromCache() throws Exception {
        TestJWKSetSource source = new TestJWKSetSource(new JWKSet(key.toPublicJWK()));
        JWKSource<SecurityContext> jwkSource = jwkSource(source, new ListEventListener(), 0);

        AtomicInteger decodes = new AtomicInteger();
        decoder(jwkSource, decodes);

        String token = token(key, "a");
        decoder.decode(token);
        decoder.decode(token);
        assertEquals(1, decoder.getSize());
        assertEquals(1, decodes.get());

        // same header and claims as the cached JWT, but another signature
        int signatureStart = token.lastIndexOf('.') + 1;
        int index = signatureStart + (token.length() - signatureStart) / 2;
        char replacement = token.charAt(index) == 'A' ? 'B' : 'A';
        String tampered = token.substring(0, index) + replacement + token.substring(index + 1);

        // the signature is verified, i.e. the cache is keyed by the complete JWT
        assertThrows(JwtException.class, () -> decoder.decode(tampered));
        assertEquals(2, decodes.get());
        assertEquals(1, decoder.getSize());

        // the valid JWT is still served from the cache
        decoder.decode(token);
        assertEquals(2, decodes.get());
    }
}
