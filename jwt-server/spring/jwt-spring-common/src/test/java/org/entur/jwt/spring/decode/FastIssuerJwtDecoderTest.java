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
import org.entur.jwt.spring.decode.cache.DecodedJwtCacheJwtDecoder;
import org.entur.jwt.spring.properties.jwk.JwtDecoderCacheProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link FastIssuerJwtDecoder} with issuers whose JWTs have identical headers, i.e. which share a signing key and key id,
 * with real JWK sources and signed JWTs.
 */
class FastIssuerJwtDecoderTest {

    private static final String ISSUER_A = "https://issuer.a";
    private static final String ISSUER_B = "https://issuer.b";

    private static RSAKey sharedKey;
    private static RSAKey otherKeyWithSameKeyId;

    private final Map<String, AtomicInteger> decodeCounts = new ConcurrentHashMap<>();
    private final JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();

    private ClosableJwtDecoders decoders;

    @BeforeAll
    static void createKeys() throws Exception {
        sharedKey = new RSAKeyGenerator(2048).keyID("shared").generate();
        otherKeyWithSameKeyId = new RSAKeyGenerator(2048).keyID("shared").generate();
    }

    @AfterEach
    void close() {
        if (decoders != null) {
            decoders.close();
        }
    }

    @Test
    void testDecodesTokensOfIssuersWithSameHeader() throws Exception {
        FastIssuerJwtDecoder decoder = decoder(sharedKey, sharedKey, false);

        assertDecodesTokensOfBothIssuers(decoder, token(sharedKey, ISSUER_A), token(sharedKey, ISSUER_B));
    }

    @Test
    void testDecodesTokensOfIssuersWithSameHeaderInReverseOrder() throws Exception {
        FastIssuerJwtDecoder decoder = decoder(sharedKey, sharedKey, false);

        assertDecodesTokensOfBothIssuers(decoder, token(sharedKey, ISSUER_B), token(sharedKey, ISSUER_A));
    }

    @Test
    void testDecodesTokensOfIssuersWithSameHeaderButDifferentKeys() throws Exception {
        // i.e. the same (static) key id for different keys
        FastIssuerJwtDecoder decoder = decoder(sharedKey, otherKeyWithSameKeyId, false);

        assertDecodesTokensOfBothIssuers(decoder, token(sharedKey, ISSUER_A), token(otherKeyWithSameKeyId, ISSUER_B));
    }

    @Test
    void testDecodesTokensOfIssuersWithSameHeaderAndDecodedJwtCache() throws Exception {
        FastIssuerJwtDecoder decoder = decoder(sharedKey, sharedKey, true);

        assertDecodesTokensOfBothIssuers(decoder, token(sharedKey, ISSUER_A), token(sharedKey, ISSUER_B));

        DecodedJwtCacheJwtDecoder cache = (DecodedJwtCacheJwtDecoder) decoders.getJwtDecoders().get(ISSUER_A);
        assertThat(cache.getSize()).isEqualTo(1);
    }

    private void assertDecodesTokensOfBothIssuers(FastIssuerJwtDecoder decoder, String first, String second) {
        assertThat(header(first)).isEqualTo(header(second));
        String firstIssuer = decoder.decode(first).getClaim("iss");
        String secondIssuer = decoder.decode(second).getClaim("iss");
        assertThat(firstIssuer).isNotEqualTo(secondIssuer);

        // the header no longer identifies the issuer
        assertThat(mapper.get(first)).isNull();
        assertThat(mapper.getSharedHeaders()).containsExactly(header(first));

        assertThat(decoder.decode(first).<String>getClaim("iss")).isEqualTo(firstIssuer);
        assertThat(decoder.decode(second).<String>getClaim("iss")).isEqualTo(secondIssuer);
        assertThat(decoder.decode(first).<String>getClaim("iss")).isEqualTo(firstIssuer);
        assertThat(mapper.get(first)).isNull();
    }

    @Test
    void testDoesNotDecodeInvalidTokenOfMappedIssuerAgain() throws Exception {
        FastIssuerJwtDecoder decoder = decoder(sharedKey, sharedKey, false);
        decoder.decode(token(sharedKey, ISSUER_A));
        decodeCounts.clear();

        String expired = token(sharedKey, ISSUER_A, new Date(System.currentTimeMillis() - 3_600_000));

        assertThatThrownBy(() -> decoder.decode(expired)).isInstanceOf(JwtValidationException.class);
        assertThat(decodeCounts.get(ISSUER_A)).hasValue(1);
        assertThat(decodeCounts).doesNotContainKey(ISSUER_B);
        assertThat(mapper.get(expired)).isEqualTo(ISSUER_A);
    }

    @Test
    void testRejectsInvalidTokenOfOtherIssuerWithSameHeader() throws Exception {
        FastIssuerJwtDecoder decoder = decoder(sharedKey, sharedKey, false);
        decoder.decode(token(sharedKey, ISSUER_A));

        String expired = token(sharedKey, ISSUER_B, new Date(System.currentTimeMillis() - 3_600_000));

        assertThatThrownBy(() -> decoder.decode(expired)).isInstanceOf(JwtValidationException.class);
        // not verified for the other issuer, so the header is still mapped
        assertThat(mapper.get(expired)).isEqualTo(ISSUER_A);
    }

    @Test
    void testRejectsForgedTokenOfOtherIssuerWithSameHeader() throws Exception {
        FastIssuerJwtDecoder decoder = decoder(sharedKey, sharedKey, false);
        decoder.decode(token(sharedKey, ISSUER_A));

        // i.e. an attempt to make the header map to another issuer
        String forged = token(otherKeyWithSameKeyId, ISSUER_B);

        assertThatThrownBy(() -> decoder.decode(forged)).isInstanceOf(JwtException.class);
        assertThat(mapper.get(forged)).isEqualTo(ISSUER_A);
        assertThat(mapper.getSharedHeaders()).isEmpty();
    }

    @Test
    void testRejectsTokenOfUnknownIssuerWithSameHeader() throws Exception {
        FastIssuerJwtDecoder decoder = decoder(sharedKey, sharedKey, false);
        decoder.decode(token(sharedKey, ISSUER_A));

        String unknown = token(sharedKey, "https://unknown.issuer");

        assertThatThrownBy(() -> decoder.decode(unknown)).isInstanceOf(JwtException.class).hasMessageContaining("Unknown issuer");
        assertThat(mapper.get(unknown)).isEqualTo(ISSUER_A);
        assertThat(mapper.getSharedHeaders()).isEmpty();
    }

    private FastIssuerJwtDecoder decoder(RSAKey keyA, RSAKey keyB, boolean decodedJwtCacheA) {
        ClosableJwtDecodersBuilder builder = new ClosableJwtDecodersBuilder()
                .withJwkSources(Map.of(ISSUER_A, jwkSource(keyA), ISSUER_B, jwkSource(keyB)))
                .withJwtValidators(List.of());
        if (decodedJwtCacheA) {
            builder.withDecodedJwtCacheIssuers(Map.of(ISSUER_A, new JwtDecoderCacheProperties()));
        }
        decoders = builder.build();

        // count the decodings per issuer
        Map<String, JwtDecoder> counting = new HashMap<>();
        for (Map.Entry<String, JwtDecoder> entry : decoders.getJwtDecoders().entrySet()) {
            counting.put(entry.getKey(), token -> {
                decodeCounts.computeIfAbsent(entry.getKey(), k -> new AtomicInteger()).incrementAndGet();
                return entry.getValue().decode(token);
            });
        }
        return new FastIssuerJwtDecoder(counting, mapper, new DefaultJwtHeaderToIssuerMapperDecider());
    }

    private static JWKSource jwkSource(RSAKey key) {
        return new ImmutableJWKSet<>(new JWKSet(key.toPublicJWK()));
    }

    private static String token(RSAKey key, String issuer) throws Exception {
        return token(key, issuer, new Date(System.currentTimeMillis() + 3_600_000));
    }

    private static String token(RSAKey key, String issuer, Date expirationTime) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject("subject")
                .expirationTime(expirationTime)
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private static String header(String token) {
        return token.substring(0, token.indexOf('.'));
    }
}
