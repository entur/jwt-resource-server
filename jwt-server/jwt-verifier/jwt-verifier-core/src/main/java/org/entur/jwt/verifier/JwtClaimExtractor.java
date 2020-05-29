package org.entur.jwt.verifier;

import java.io.Serializable;
import java.util.Map;

/**
 * Extract claims from a token. Basic JSON-types are supported. 
 * 
 * Note that all integer numbers must be of Long type.
 * 
 * @param <T> token type
 */

public interface JwtClaimExtractor<T> extends Serializable { // Serializable as will be stored in Authentication

    <V> V getClaim(T token, String name, Class<V> type) throws JwtClaimException;

    Map<String, Object> getClaims(T token) throws JwtClaimException;

}
