package org.entur.jwt.spring.decode.cache;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.entur.jwt.spring.decode.ClosableJwtDecoders;
import org.entur.jwt.spring.decode.ClosableJwtDecodersBuilder;
import org.entur.jwt.spring.properties.jwk.JwtDecoderCacheProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The decoded JWT cache of the decoders built by {@link ClosableJwtDecodersBuilder}, with real JWK sources and signed JWTs.
 */
class ClosableJwtDecodersBuilderCacheTest {

    private static final String ISSUER_A = "https://issuer.a";
    private static final String ISSUER_B = "https://issuer.b";

    private static RSAKey keyA;
    private static RSAKey keyB;
    private static RSAKey rotatedKeyA;

    private final AtomicBoolean claimsValid = new AtomicBoolean(true);

    // i.e. like the expiry / audience validators
    private final OAuth2TokenValidator<Jwt> claimValidator = jwt -> claimsValid.get()
            ? OAuth2TokenValidatorResult.success()
            : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Simulated invalid claims", null));

    private TestJWKSetSource jwkSetSourceA;
    private JWKSource<SecurityContext> jwkSourceA;
    private ClosableJwtDecoders decoders;

    @BeforeAll
    static void createKeys() throws Exception {
        keyA = new RSAKeyGenerator(2048).keyID("a").generate();
        keyB = new RSAKeyGenerator(2048).keyID("b").generate();
        rotatedKeyA = new RSAKeyGenerator(2048).keyID("a2").generate();
    }

    @AfterEach
    void close() throws Exception {
        if (decoders != null) {
            decoders.close();
        }
    }

    private static JWKSource<SecurityContext> jwkSource(TestJWKSetSource jwkSetSource) {
        return JWKSourceBuilder.create(jwkSetSource)
                .rateLimited(false)
                .cache(60_000, 1_000)
                .refreshAheadCache(false)
                .retrying(false)
                .outageTolerant(false)
                .build();
    }

    private static String token(RSAKey key, String issuer) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject("subject")
                .expirationTime(new Date(System.currentTimeMillis() + 3_600_000))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private ClosableJwtDecoders build(int cleanupIntervalSeconds) throws Exception {
        jwkSetSourceA = new TestJWKSetSource(new JWKSet(keyA.toPublicJWK()));
        jwkSourceA = jwkSource(jwkSetSourceA);

        JwtDecoderCacheProperties cache = new JwtDecoderCacheProperties();
        cache.setEnabled(true);
        cache.setSize(10);
        cache.setCleanupInterval(cleanupIntervalSeconds);

        decoders = new ClosableJwtDecodersBuilder()
                .withJwkSources(Map.of(ISSUER_A, jwkSourceA, ISSUER_B, jwkSource(new TestJWKSetSource(new JWKSet(keyB.toPublicJWK())))))
                .withJwtValidators(List.of(claimValidator))
                .withDecodedJwtCacheIssuers(Map.of(ISSUER_A, cache))
                .build();

        // load the JWK set, so that the first JWT is cached
        jwkSourceA.get(new JWKSelector(new JWKMatcher.Builder().build()), null);

        return decoders;
    }

    @Test
    void testOnlyTenantsWithDecoderCacheAreCached() throws Exception {
        build(-1);

        assertThat(decoders.getJwtDecoders().get(ISSUER_A)).isInstanceOf(DecodedJwtCacheJwtDecoder.class);
        assertThat(decoders.getJwtDecoders().get(ISSUER_B)).isInstanceOf(NimbusJwtDecoder.class);
    }

    @Test
    void testCacheHitRunsConfiguredClaimValidators() throws Exception {
        build(-1);
        DecodedJwtCacheJwtDecoder decoder = (DecodedJwtCacheJwtDecoder) decoders.getJwtDecoders().get(ISSUER_A);
        String token = token(keyA, ISSUER_A);

        decoder.decode(token);
        assertThat(decoder.getSize()).isEqualTo(1);

        // the claims are no longer valid (i.e. expired): the cached JWT must be rejected and evicted
        claimsValid.set(false);
        assertThrows(JwtException.class, () -> decoder.decode(token));
        assertThat(decoder.getSize()).isEqualTo(0);
    }

    @Test
    void testCachedDecoderValidatesIssuer() throws Exception {
        build(-1);
        JwtDecoder decoder = decoders.getJwtDecoders().get(ISSUER_A);

        // signed with the tenant's key, but issued by someone else
        String token = token(keyA, "https://other.issuer");

        assertThrows(JwtException.class, () -> decoder.decode(token));
        assertThat(((DecodedJwtCacheJwtDecoder) decoder).getSize()).isEqualTo(0);
    }

    @Test
    void testCachedDecoderFollowsJwkSource() throws Exception {
        build(-1);
        DecodedJwtCacheJwtDecoder decoder = (DecodedJwtCacheJwtDecoder) decoders.getJwtDecoders().get(ISSUER_A);
        String token = token(keyA, ISSUER_A);

        decoder.decode(token);
        assertThat(decoder.getSize()).isEqualTo(1);

        // key rotation: the JWK set is reloaded on the first JWT signed with the new key
        jwkSetSourceA.setJwkSet(new JWKSet(rotatedKeyA.toPublicJWK()));
        decoder.decode(token(rotatedKeyA, ISSUER_A));

        // the cache checks against the decoder's JWK source, which no longer has the key of the cached JWT
        assertThrows(JwtException.class, () -> decoder.decode(token));
    }

    @Test
    void testCloseStopsCleanupThread() throws Exception {
        build(60);
        DecodedJwtCacheJwtDecoder decoder = (DecodedJwtCacheJwtDecoder) decoders.getJwtDecoders().get(ISSUER_A);
        assertThat(decoder.scheduledExecutorService).isNotNull();

        // named after the issuer, so that threads of different tenants can be told apart
        assertThat(decoder.getName()).isEqualTo(ISSUER_A);
        Thread thread = decoder.scheduledExecutorService.submit(Thread::currentThread).get(5, TimeUnit.SECONDS);
        assertThat(thread.getName()).isEqualTo("decoded-jwt-cache-cleanup-" + ISSUER_A);

        decoders.close();

        assertThat(decoder.scheduledExecutorService.isShutdown()).isTrue();
        decoders = null;
    }
}
