package org.entur.jwt.spring.decode;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
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

    private ClosableJwtDecoders decoders;

    @BeforeAll
    static void createKeys() throws Exception {
        keyA = new RSAKeyGenerator(2048).keyID("a").generate();
        keyB = new RSAKeyGenerator(2048).keyID("b").generate();
    }

    @AfterEach
    void close() {
        if (decoders != null) {
            decoders.close();
        }
    }

    private static JWKSource jwkSource(RSAKey key) {
        return new ImmutableJWKSet<>(new JWKSet(key.toPublicJWK()));
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

    private ClosableJwtDecoders build() {
        decoders = new ClosableJwtDecodersBuilder()
                .withJwkSources(Map.of(ISSUER_A, jwkSource(keyA), ISSUER_B, jwkSource(keyB)))
                .withJwtValidators(List.of(claimValidator))
                .build();
        return decoders;
    }

    @Test
    void testOneDecoderPerIssuer() {
        build();

        assertThat(decoders.getJwtDecoders()).containsOnlyKeys(ISSUER_A, ISSUER_B);
    }

    @Test
    void testDecodesTokenOfTenant() throws Exception {
        build();
        JwtDecoder decoder = decoders.getJwtDecoders().get(ISSUER_A);

        Jwt jwt = decoder.decode(token(keyA, ISSUER_A));

        assertThat(jwt.getIssuer()).hasToString(ISSUER_A);
        assertThat(jwt.getSubject()).isEqualTo("subject");
    }

    @Test
    void testRunsConfiguredClaimValidators() throws Exception {
        build();
        JwtDecoder decoder = decoders.getJwtDecoders().get(ISSUER_A);
        String token = token(keyA, ISSUER_A);

        claimsValid.set(false);

        assertThrows(JwtException.class, () -> decoder.decode(token));
    }

    @Test
    void testValidatesIssuer() throws Exception {
        build();
        JwtDecoder decoder = decoders.getJwtDecoders().get(ISSUER_A);

        // signed with the tenant's key, but issued by someone else
        String token = token(keyA, "https://other.issuer");

        assertThrows(JwtException.class, () -> decoder.decode(token));
    }

    @Test
    void testRejectsTokenSignedWithKeyOfOtherTenant() throws Exception {
        build();
        JwtDecoder decoder = decoders.getJwtDecoders().get(ISSUER_A);

        String token = token(keyB, ISSUER_A);

        assertThrows(JwtException.class, () -> decoder.decode(token));
    }
}
