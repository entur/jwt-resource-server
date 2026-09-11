package org.entur.jwt.spring.decode.cache;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Back-to-back-request benchmark of {@link DecodedJwtCacheJwtDecoder}, run manually (not
 * part of the regular build) to get a ballpark of the speedup the decoded-JWT cache gives
 * over always fully re-verifying the JWT signature (i.e. behaviour without this cache,
 * as on {@code master}).
 * <p>
 * Three scenarios are simulated, each issuing {@link #REQUESTS} decode calls back to back
 * on a single thread, after a warm-up phase to let the JIT settle:
 * <ul>
 *     <li>{@code baselineNoCache} - every request is fully verified, no cache involved.
 *     This approximates {@code master} for every request, and also the decoded-JWT cache's
 *     worst case (a cache miss).</li>
 *     <li>{@code singleTokenReused} - a single token is decoded over and over, i.e. a
 *     100% cache-hit rate. This approximates a single long-lived client-credentials token
 *     reused for many outgoing service-to-service requests.</li>
 *     <li>{@code tokenPoolReused} - a small pool of distinct tokens (simulating several
 *     concurrent clients/tenants) is cycled through repeatedly, i.e. a more realistic
 *     mixed workload with a high but not 100% cache-hit rate.</li>
 * </ul>
 * To run: remove/comment out {@code @Disabled} and execute this test class directly.
 */
@Tag("performance")
@Disabled("Manual benchmark - not meant to run as part of the regular build")
public class DecodedJwtCacheJwtDecoderBenchmarkTest {

    private static final int WARMUP_REQUESTS = 20_000;
    private static final int REQUESTS = 200_000;
    private static final int TOKEN_POOL_SIZE = 50;

    @Test
    public void baselineNoCache() throws Exception {
        RSAKey signingKey = generateRsaKey("kid-0");
        JwtDecoder delegate = nimbusDecoder(signingKey);
        String token = signedToken(signingKey);

        Stats stats = measure("baseline (no cache, every request fully verified)",
                REQUESTS, WARMUP_REQUESTS, i -> delegate.decode(token));

        assertTrue(stats.opsPerSecond > 0);
    }

    @Test
    public void singleTokenReused() throws Exception {
        RSAKey signingKey = generateRsaKey("kid-0");
        JwtDecoder delegate = nimbusDecoder(signingKey);
        String token = signedToken(signingKey);

        DecodedJwtCacheJwtDecoder cachedDecoder = cachedDecoder(delegate, signingKey);
        cachedDecoder.decode(token); // populate cache (first call is necessarily a miss)

        Stats baseline = measure("baseline (no cache, every request fully verified)",
                REQUESTS, WARMUP_REQUESTS, i -> delegate.decode(token));

        Stats cached = measure("single token reused (100% cache-hit rate)",
                REQUESTS, WARMUP_REQUESTS, i -> cachedDecoder.decode(token));

        printSpeedup(baseline, cached);

        assertTrue(cached.opsPerSecond > baseline.opsPerSecond,
                "Cache-hit decoding is expected to be substantially faster than full re-verification");
    }

    @Test
    public void tokenPoolReused() throws Exception {
        RSAKey signingKey = generateRsaKey("kid-0");
        JwtDecoder delegate = nimbusDecoder(signingKey);

        List<String> tokens = new ArrayList<>(TOKEN_POOL_SIZE);
        for (int i = 0; i < TOKEN_POOL_SIZE; i++) {
            tokens.add(signedToken(signingKey));
        }

        DecodedJwtCacheJwtDecoder cachedDecoder = cachedDecoder(delegate, signingKey);
        for (String token : tokens) {
            cachedDecoder.decode(token); // populate cache for each token in the pool
        }

        Stats baseline = measure("baseline (no cache, every request fully verified)",
                REQUESTS, WARMUP_REQUESTS, i -> delegate.decode(tokens.get(i % tokens.size())));

        Stats cached = measure("token pool of " + TOKEN_POOL_SIZE + " reused round-robin (simulated multi-client traffic)",
                REQUESTS, WARMUP_REQUESTS, i -> cachedDecoder.decode(tokens.get(i % tokens.size())));

        printSpeedup(baseline, cached);

        assertTrue(cached.opsPerSecond > baseline.opsPerSecond,
                "Cache-hit decoding with a reused token pool is expected to be substantially faster than full re-verification");
    }

    // --- helpers -------------------------------------------------------------------

    private interface DecodeCall {
        void decode(int i) throws Exception;
    }

    private record Stats(String label, double avgLatencyMicros, double opsPerSecond) {
    }

    /**
     * Runs {@code call} back to back {@code requests} times (after a warm-up phase of
     * {@code warmup} calls to let the JIT settle), then reports average per-call latency
     * and throughput.
     */
    private Stats measure(String label, int requests, int warmup, DecodeCall call) throws Exception {
        for (int i = 0; i < warmup; i++) {
            call.decode(i);
        }

        long start = System.nanoTime();
        for (int i = 0; i < requests; i++) {
            call.decode(i);
        }
        long durationNanos = System.nanoTime() - start;

        double avgLatencyMicros = (durationNanos / 1000.0) / requests;
        double opsPerSecond = requests / (durationNanos / 1_000_000_000.0);

        System.out.printf("[%s] %.3f us/op, %.0f ops/sec (%d requests back to back)%n",
                label, avgLatencyMicros, opsPerSecond, requests);

        return new Stats(label, avgLatencyMicros, opsPerSecond);
    }

    private void printSpeedup(Stats baseline, Stats cached) {
        System.out.printf("Speedup vs baseline: %.1fx (latency), %.1fx (throughput)%n%n",
                baseline.avgLatencyMicros / cached.avgLatencyMicros,
                cached.opsPerSecond / baseline.opsPerSecond);
    }

    private JwtDecoder nimbusDecoder(RSAKey signingKey) throws Exception {
        return NimbusJwtDecoder.withPublicKey((RSAPublicKey) signingKey.toRSAPublicKey()).build();
    }

    private String signedToken(RSAKey signingKey) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("test-subject")
                .issuer("https://issuer.example.com")
                .audience("test-audience")
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .issueTime(new Date())
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claims);
        signedJWT.sign(new RSASSASigner(signingKey));
        return signedJWT.serialize();
    }

    /**
     * Wraps {@code delegate} with a {@link DecodedJwtCacheJwtDecoder}, and feeds it a
     * simulated JWKS refresh so it treats {@code signingKey}'s key id as an active
     * signing key (required before it will actually cache any decoded JWT).
     */
    @SuppressWarnings("unchecked")
    private DecodedJwtCacheJwtDecoder cachedDecoder(JwtDecoder delegate, RSAKey signingKey) {
        DecodedJwtCacheJwtDecoder cachedDecoder = new DecodedJwtCacheJwtDecoder(
                delegate, jwt -> OAuth2TokenValidatorResult.success(), 0L, -1);

        JWKSet jwkSet = new JWKSet(List.of(signingKey.toPublicJWK()));
        CachingJWKSetSource.RefreshCompletedEvent<?> event = mock(CachingJWKSetSource.RefreshCompletedEvent.class);
        when(event.getJWKSet()).thenReturn(jwkSet);
        cachedDecoder.notify(event);

        return cachedDecoder;
    }

    private RSAKey generateRsaKey(String kid) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair pair = gen.generateKeyPair();
        return new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                .privateKey(pair.getPrivate())
                .keyID(kid)
                .build();
    }
}
