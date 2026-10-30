package org.entur.jwt.junit5.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.JsonNodeType;

import java.math.BigInteger;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class DefaultAuthorizationServerEncoderTest {

    private static final JsonMapper JSON_MAPPER = JsonMapper.builder().build();

    private final DefaultAuthorizationServerEncoder encoder = new DefaultAuthorizationServerEncoder();

    @Test
    public void testJsonWebKeysUseBase64UrlUIntEncoding() throws Exception {
        JWKSet jwkSet = JWKSet.parse(encoder.getJsonWebKeys(null));
        RSAKey key = (RSAKey) jwkSet.getKeys().get(0);

        for (String value : new String[] { key.getModulus().toString(), key.getPublicExponent().toString() }) {
            // no padding
            assertThat(value).doesNotContain("=");
            // no leading zero (sign) byte
            assertThat(Base64.getUrlDecoder().decode(value)[0]).isNotEqualTo((byte) 0);
        }
        // 2048 bits
        assertThat(key.getModulus().decode()).hasLength(256);
        assertThat(key.getPublicExponent().decodeToBigInteger()).isEqualTo(BigInteger.valueOf(65537));
    }

    @Test
    public void testTokenCanBeVerifiedUsingJsonWebKeys() throws Exception {
        RSAKey key = (RSAKey) JWKSet.parse(encoder.getJsonWebKeys(null)).getKeys().get(0);

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "mySubject");

        SignedJWT jwt = SignedJWT.parse(encoder.getToken(null, claims, new HashMap<>()));

        assertThat(jwt.getHeader().getKeyID()).isEqualTo(key.getKeyID());
        assertThat(jwt.verify(new RSASSAVerifier(key))).isTrue();
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("mySubject");
    }

    @Test
    public void testClaimsAreWrittenAsGiven() throws Exception {
        RSAKey key = (RSAKey) JWKSet.parse(encoder.getJsonWebKeys(null)).getKeys().get(0);

        // standard claims of unexpected types
        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", 5);
        claims.put("sub", new String[] { "a", "b" });
        claims.put("aud", "myAudience");
        claims.put("exp", "1700000000");
        claims.put("nbf", true);
        claims.put("iat", 1.5);
        claims.put("jti", null);

        SignedJWT jwt = SignedJWT.parse(encoder.getToken(null, claims, new HashMap<>()));
        assertThat(jwt.verify(new RSASSAVerifier(key))).isTrue();

        JsonNode payload = JSON_MAPPER.readTree(jwt.getPayload().toString());
        assertThat(payload.get("iss").getNodeType()).isEqualTo(JsonNodeType.NUMBER);
        assertThat(payload.get("sub").getNodeType()).isEqualTo(JsonNodeType.ARRAY);
        assertThat(payload.get("aud").getNodeType()).isEqualTo(JsonNodeType.STRING);
        assertThat(payload.get("exp").getNodeType()).isEqualTo(JsonNodeType.STRING);
        assertThat(payload.get("nbf").getNodeType()).isEqualTo(JsonNodeType.BOOLEAN);
        assertThat(payload.get("iat").doubleValue()).isEqualTo(1.5);
        assertThat(payload.get("jti").isNull()).isTrue();
    }

    @Test
    public void testDatesInDateClaimsAreWrittenAsSeconds() throws Exception {
        Date date = new Date(1700000000123L);
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);

        Map<String, Object> claims = new HashMap<>();
        claims.put("exp", date);
        claims.put("nbf", calendar);
        claims.put("iat", 1700000000L);
        claims.put("myDate", date);

        JsonNode payload = JSON_MAPPER.readTree(SignedJWT.parse(encoder.getToken(null, claims, new HashMap<>())).getPayload().toString());

        assertThat(payload.get("exp").longValue()).isEqualTo(1700000000L);
        assertThat(payload.get("nbf").longValue()).isEqualTo(1700000000L);
        assertThat(payload.get("iat").longValue()).isEqualTo(1700000000L);
        // like the JWT library, other claims are in milliseconds
        assertThat(payload.get("myDate").longValue()).isEqualTo(1700000000123L);
    }

    @ParameterizedTest
    @ValueSource(strings = { "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" })
    public void testTokenCanBeVerifiedForAlgorithm(String algorithm) throws Exception {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "mySubject");

        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", algorithm);

        String token = encoder.getToken(null, claims, headers);
        assertThat(SignedJWT.parse(token).getHeader().getAlgorithm().getName()).isEqualTo(algorithm);

        // select the key like the resource server does
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.Family.SIGNATURE, new ImmutableJWKSet<>(JWKSet.parse(encoder.getJsonWebKeys(null)))));

        JWTClaimsSet claimsSet = processor.process(token, null);
        assertThat(claimsSet.getSubject()).isEqualTo("mySubject");
    }

    @ParameterizedTest
    @ValueSource(strings = { "HS256", "none" })
    public void testUnsupportedAlgorithm(String algorithm) {
        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", algorithm);

        assertThrows(IllegalArgumentException.class, () -> encoder.getToken(null, new HashMap<>(), headers));
    }

    @Test
    public void testJsonWebKeysEllipticCurveCoordinateSize() throws Exception {
        Map<String, Integer> sizes = new HashMap<>();
        sizes.put("P-256", 32);
        sizes.put("P-384", 48);
        sizes.put("P-521", 66);

        for (JWK jwk : JWKSet.parse(encoder.getJsonWebKeys(null)).getKeys()) {
            if (jwk instanceof ECKey) {
                ECKey key = (ECKey) jwk;
                int size = sizes.remove(key.getCurve().getName());

                assertThat(key.getX().decode()).hasLength(size);
                assertThat(key.getY().decode()).hasLength(size);
            }
        }
        assertThat(sizes).isEmpty();
    }

    @Test
    public void testBase64UrlUInt() {
        assertThat(DefaultAuthorizationServerEncoder.toBase64UrlUInt(BigInteger.ZERO)).isEqualTo("AA");
        assertThat(DefaultAuthorizationServerEncoder.toBase64UrlUInt(BigInteger.valueOf(65537))).isEqualTo("AQAB");
        // 255 is 0x00FF as a signed two's-complement byte array
        assertThat(DefaultAuthorizationServerEncoder.toBase64UrlUInt(BigInteger.valueOf(255))).isEqualTo("_w");
    }
}
