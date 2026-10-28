package org.entur.jwt.junit5.impl;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static com.google.common.truth.Truth.assertThat;

public class DefaultAuthorizationServerEncoderTest {

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
    public void testBase64UrlUInt() {
        assertThat(DefaultAuthorizationServerEncoder.toBase64UrlUInt(BigInteger.ZERO)).isEqualTo("AA");
        assertThat(DefaultAuthorizationServerEncoder.toBase64UrlUInt(BigInteger.valueOf(65537))).isEqualTo("AQAB");
        // 255 is 0x00FF as a signed two's-complement byte array
        assertThat(DefaultAuthorizationServerEncoder.toBase64UrlUInt(BigInteger.valueOf(255))).isEqualTo("_w");
    }
}
