package org.entur.jwt.jwk;

/**
 * Wrapper interface in order to support arbitrary implementations.
 * 
 * @param <T> type of Jwk key
 */

public interface JwkFieldExtractor<T> {

    String getJwkId(T jwk);
}
