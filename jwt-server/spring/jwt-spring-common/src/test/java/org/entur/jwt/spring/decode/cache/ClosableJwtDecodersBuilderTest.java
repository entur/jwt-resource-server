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
import org.entur.jwt.spring.actuate.ListEventListener;
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
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The decoders built by {@link ClosableJwtDecodersBuilder}, with real JWK sources and signed JWTs.
 */
class ClosableJwtDecodersBuilderTest {

    private static final String ISSUER_A = "https://issuer.a";
    private static final String ISSUER_B = "https://issuer.b";

    private static RSAKey keyA;
    private static RSAKey keyB;

    private final AtomicBoolean claimsValid = new AtomicBoolean(true);

    // i.e. like the expiry / audience validators
    private final OAuth2TokenValidator<Jwt> claimValidator = jwt -> claimsValid.get()
            ? OAuth2TokenValidatorResult.success()
            : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Simulated invalid claims", null));

    private final ListEventListener listenerA = new ListEventListener();
    private final ListEventListener listenerB = new ListEventListener();

    private JWKSource<SecurityContext> jwkSourceA;
    private ClosableJwtDecoders decoders;

    @BeforeAll
    static void createKeys() throws Exception {
        keyA = new RSAKeyGenerator(2048).keyID("a").generate();
        keyB = new RSAKeyGenerator(2048).keyID("b").generate();
    }

    @AfterEach
    void close() throws Exception {
        if (decoders != null) {
            decoders.close();
        }
    }

    private static JWKSource<SecurityContext> jwkSource(RSAKey key, ListEventListener listener) {
        return JWKSourceBuilder.create(new TestJWKSetSource(new JWKSet(key.toPublicJWK())))
                .rateLimited(false)
                .cache(60_000, 1_000, listener)
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
        jwkSourceA = jwkSource(keyA, listenerA);

        JwtDecoderCacheProperties cache = new JwtDecoderCacheProperties();
        cache.setEnabled(true);
        cache.setSize(10);
        cache.setCleanupInterval(cleanupIntervalSeconds);

        decoders = new ClosableJwtDecodersBuilder()
                .withJwkSources(Map.of(ISSUER_A, jwkSourceA, ISSUER_B, jwkSource(keyB, listenerB)))
                .withJwkEventListeners(Map.of(ISSUER_A, listenerA, ISSUER_B, listenerB))
                .withJwtValidators(List.of(claimValidator))
                .withDecodedJwtCacheIssuers(Map.of(ISSUER_A, cache))
                .build();

        // load the JWK set, so that the first JWT is cached
        jwkSourceA.get(new JWKSelector(new JWKMatcher.Builder().build()), null);

        return decoders;
    }

    @Test
    void testCacheWithoutJwkEventListenerFailsBuild() {
        JwtDecoderCacheProperties cache = new JwtDecoderCacheProperties();
        cache.setEnabled(true);
        cache.setSize(10);
        cache.setCleanupInterval(-1);

        // listener for another issuer only
        ClosableJwtDecodersBuilder builder = new ClosableJwtDecodersBuilder()
                .withJwkSources(Map.of(ISSUER_A, jwkSource(keyA, listenerA)))
                .withJwkEventListeners(Map.of(ISSUER_B, listenerB))
                .withJwtValidators(List.of(claimValidator))
                .withDecodedJwtCacheIssuers(Map.of(ISSUER_A, cache));

        assertThatThrownBy(builder::build)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(ISSUER_A)
                .hasMessageContaining("withJwkEventListeners");

        // no listeners at all
        ClosableJwtDecodersBuilder builderWithoutListeners = new ClosableJwtDecodersBuilder()
                .withJwkSources(Map.of(ISSUER_A, jwkSource(keyA, listenerA)))
                .withJwtValidators(List.of(claimValidator))
                .withDecodedJwtCacheIssuers(Map.of(ISSUER_A, cache));

        assertThatThrownBy(builderWithoutListeners::build)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(ISSUER_A);
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
    void testCachedDecoderFollowsJwkEvents() throws Exception {
        build(-1);
        DecodedJwtCacheJwtDecoder decoder = (DecodedJwtCacheJwtDecoder) decoders.getJwtDecoders().get(ISSUER_A);

        // the builder registered the decoder with the tenant's JWK event listener, which got the JWK set load
        assertThat(decoder.cache.keyRepresentations.contains("a")).isTrue();
    }

    @Test
    void testCloseStopsCleanupThread() throws Exception {
        build(60);
        DecodedJwtCacheJwtDecoder decoder = (DecodedJwtCacheJwtDecoder) decoders.getJwtDecoders().get(ISSUER_A);
        assertThat(decoder.scheduledExecutorService).isNotNull();

        decoders.close();

        assertThat(decoder.scheduledExecutorService.isShutdown()).isTrue();
        decoders = null;
    }
}
