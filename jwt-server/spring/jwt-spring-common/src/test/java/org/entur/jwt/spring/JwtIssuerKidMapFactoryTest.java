package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class JwtIssuerKidMapFactoryTest {

    @Test
    void shouldCreateKidMapWhenKidsAreUniqueAcrossIssuers() {
        Map<String, JWKSource> sources = Map.of(
                "https://issuer-1.example", source("kid-1"),
                "https://issuer-2.example", source("kid-2"));

        Map<String, String> kidMap = JwtIssuerKidMapFactory.createKidToIssuer(sources);

        assertThat(kidMap).containsEntry("kid-1", "https://issuer-1.example");
        assertThat(kidMap).containsEntry("kid-2", "https://issuer-2.example");
    }

    @Test
    void shouldReturnEmptyMapWhenKidsOverlapBetweenIssuers() {
        Map<String, JWKSource> sources = Map.of(
                "https://issuer-1.example", source("shared-kid"),
                "https://issuer-2.example", source("shared-kid"));

        assertThat(JwtIssuerKidMapFactory.createKidToIssuer(sources)).isEmpty();
    }

    private static JWKSource source(String kid) {
        JWK key = new OctetSequenceKey.Builder(new com.nimbusds.jose.util.Base64URL("AQIDBAUGBwgJCgsMDQ4PEA"))
                .keyID(kid)
                .build();
        return new ImmutableJWKSet(new JWKSet(key));
    }
}
