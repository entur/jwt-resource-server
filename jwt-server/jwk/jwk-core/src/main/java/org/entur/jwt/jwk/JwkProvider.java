package org.entur.jwt.jwk;

/**
 * Provider of individual Jwk keys.
 */

public interface JwkProvider<T> extends JwksProvider<T> {
    /**
     * Returns a jwk using the kid value
     * 
     * @param keyId value of kid found in JWT
     * @return a jwk
     * @throws JwksException if no jwk can be found using the given kid
     */
    T getJwk(String keyId) throws JwksException;

}
