package org.entur.jwt.spring.decode.cache;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSetCacheRefreshEvaluator;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSetUnavailableException;
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
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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

    static class SwitchableJWKSetSource implements JWKSetSource<SecurityContext> {

        private final JWKSet jwkSet;
        private volatile boolean fail;

        SwitchableJWKSetSource(JWKSet jwkSet) {
            this.jwkSet = jwkSet;
        }

        @Override
        public JWKSet getJWKSet(JWKSetCacheRefreshEvaluator refreshEvaluator, long currentTime, SecurityContext context) throws JWKSetUnavailableException {
            if (fail) {
                throw new JWKSetUnavailableException("Simulated outage");
            }
            return jwkSet;
        }

        @Override
        public void close() {
        }
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

    private static JWKSource<SecurityContext> jwkSource(JWKSetSource<SecurityContext> source, ListEventListener listener, boolean outageTolerant) {
        // similar to JwkSourceMapFactory, with eager (scheduled) refresh-ahead
        JWKSourceBuilder<SecurityContext> builder = JWKSourceBuilder.create(source)
                .rateLimited(false)
                .cache(JWK_CACHE_TIME_TO_LIVE, JWK_CACHE_REFRESH_TIMEOUT, listener)
                .refreshAheadCache(JWK_CACHE_REFRESH_AHEAD, true, listener)
                .retrying(listener);
        if (outageTolerant) {
            builder.outageTolerant(60_000, listener);
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
    void testOutageCacheDisabledFlushesWhenJwkSetServedFromJwkOutageCache() throws Exception {
        SwitchableJWKSetSource source = new SwitchableJWKSetSource(new JWKSet(key.toPublicJWK()));
        ListEventListener listener = new ListEventListener();
        JWKSource<SecurityContext> jwkSource = jwkSource(source, listener, true);

        decoder = new DecodedJwtCacheJwtDecoder(nimbusJwtDecoder(jwkSource), jwt -> OAuth2TokenValidatorResult.success(), 0, 100, false, -1);
        listener.addEventListener(decoder);

        String token = token(key, "a");
        decoder.decode(token);
        decoder.decode(token);
        assertEquals(1, decoder.getSize());

        // the JWK outage cache masks the failure as a completed refresh, but also fires an OutageEvent
        source.fail = true;
        await(() -> decoder.getSize() == 0);

        // JWTs are still accepted (verified against the JWK outage cache), but not cached
        decoder.decode(token);
        decoder.decode(token(key, "b"));
        assertEquals(0, decoder.getSize());
    }

    @Test
    void testOutageCacheTimeToLiveFlushesOnCleanupAfterFailedRefreshAhead() throws Exception {
        SwitchableJWKSetSource source = new SwitchableJWKSetSource(new JWKSet(key.toPublicJWK()));
        List<Object> events = new CopyOnWriteArrayList<>();
        ListEventListener listener = new ListEventListener();
        listener.addEventListener(events::add);
        JWKSource<SecurityContext> jwkSource = jwkSource(source, listener, false);

        long timeToLive = 2500;
        decoder = new DecodedJwtCacheJwtDecoder(nimbusJwtDecoder(jwkSource), jwt -> OAuth2TokenValidatorResult.success(), 0, 100, true, timeToLive);
        listener.addEventListener(decoder);

        String token = token(key, "a");
        decoder.decode(token);
        long loadedAt = System.currentTimeMillis();
        decoder.decode(token);
        assertEquals(1, decoder.getSize());

        source.fail = true;

        // the scheduled refresh-ahead fails once and is not rescheduled
        await(() -> events.stream().anyMatch(e -> e instanceof RefreshAheadCachingJWKSetSource.UnableToRefreshAheadOfExpirationEvent));
        assertTrue(decoder.outageDetected);

        // still within the outage time to live
        decoder.cleanup();
        assertEquals(1, decoder.getSize());
        decoder.decode(token);

        Thread.sleep(Math.max(0, loadedAt + timeToLive + 100 - System.currentTimeMillis()));

        // no further failure events, so the time to live is enforced by the cleanup
        decoder.cleanup();
        assertEquals(0, decoder.getSize());
        assertThrows(JwtException.class, () -> decoder.decode(token));

        // recovery: successful refresh resumes caching
        source.fail = false;
        decoder.decode(token);
        decoder.decode(token);
        assertEquals(1, decoder.getSize());
        assertTrue(!decoder.outageDetected);
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
                decoder.notify(refreshCompletedEvent(newJwkSet));
            }
            return jwt;
        };

        decoder = new DecodedJwtCacheJwtDecoder(delegate, jwt -> OAuth2TokenValidatorResult.success(), 0, 100);
        decoder.notify(refreshCompletedEvent(oldJwkSet));

        String token = token(oldKey, "a");
        decoder.decode(token);

        assertEquals(0, decoder.getSize());
        assertThrows(JwtException.class, () -> decoder.decode(token));
    }

    @SuppressWarnings("unchecked")
    private static CachingJWKSetSource.RefreshCompletedEvent<?> refreshCompletedEvent(JWKSet jwkSet) {
        CachingJWKSetSource.RefreshCompletedEvent<?> event = mock(CachingJWKSetSource.RefreshCompletedEvent.class);
        when(event.getJWKSet()).thenReturn(jwkSet);
        return event;
    }
}
