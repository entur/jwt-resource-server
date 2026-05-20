package org.entur.jwt.spring;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class JwtIssuerKidMapFactory {

    private JwtIssuerKidMapFactory() {
    }

    public static Map<String, String> createKidToIssuer(Map<String, JWKSource> jwkSources) {
        Map<String, String> kidToIssuer = new HashMap<>();

        for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {
            List<JWK> keys;
            try {
                keys = entry.getValue().get(new JWKSelector(new JWKMatcher.Builder().build()), null);
            } catch (KeySourceException e) {
                return Map.of();
            }

            for (JWK key : keys) {
                String keyId = key.getKeyID();
                if (keyId == null || keyId.isBlank()) {
                    continue;
                }

                String existing = kidToIssuer.putIfAbsent(keyId, entry.getKey());
                if (existing != null && !existing.equals(entry.getKey())) {
                    return Map.of();
                }
            }
        }

        return Map.copyOf(kidToIssuer);
    }
}
