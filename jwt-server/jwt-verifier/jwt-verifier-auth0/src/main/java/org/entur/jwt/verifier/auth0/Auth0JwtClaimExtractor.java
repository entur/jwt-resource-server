package org.entur.jwt.verifier.auth0;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.entur.jwt.verifier.JwtClaimException;
import org.entur.jwt.verifier.JwtClaimExtractor;

import com.auth0.jwt.impl.NullClaim;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;

import java.io.IOException;
import java.util.Base64;

/**
 * Claim key normalizer; Auth0 requires that all non-standard claims must have a
 * 'namespace' prefix. This class removes that prefix so that (for multi-tenant
 * use-cases), the same key can be used to extract claim values.
 * 
 * Integer types are not used, only Long.
 */

public class Auth0JwtClaimExtractor implements JwtClaimExtractor<DecodedJWT> {

    private static final long serialVersionUID = 1L;

    private final String normalizer; // assume non-standard claim names must be normalized

    private final ObjectReader objectReader;

    public Auth0JwtClaimExtractor(String namespace) {
        super();
        this.normalizer = namespace;

        this.objectReader = new ObjectMapper().readerFor(Map.class).with(DeserializationFeature.USE_LONG_FOR_INTS);
    }

    @Override
    public <V> V getClaim(DecodedJWT token, String name, Class<V> type) throws JwtClaimException {
        Claim claim = token.getClaim(name);
        if (normalizer != null && claim instanceof NullClaim) {
            claim = token.getClaim(normalizer + name);
        }
        if (claim instanceof NullClaim) {
            return null;
        }

        V value;
        if (type.isArray()) {
            throw new IllegalArgumentException("Array types not supported, use List");
        } else {
            value = claim.as(type);
        }
        return value;
    }

    @Override
    public Map<String, Object> getClaims(DecodedJWT token) throws JwtClaimException {
        // not ideal, but getting all claims as a map is basically not support out of
        // the box
        // decode the token again, borrowing from fusionauth-jwts JWTUtils

        try {
            Map<String, Object> claimsMap = objectReader.readValue(Base64.getUrlDecoder().decode(token.getPayload()));

            if (normalizer != null) {
                HashMap<String, Object> claims = new HashMap<>(claimsMap.size() * 2);
                for (Entry<String, Object> entry : claimsMap.entrySet()) {
                    String key = entry.getKey();
                    if (key.startsWith(normalizer)) {
                        key = key.substring(normalizer.length());
                    }
                    claims.put(key, entry.getValue());
                }
                return claims;
            } else {
                return claimsMap;
            }
        } catch (IOException e) {
            // should never happen
            throw new JwtClaimException(e);
        }
    }

}
