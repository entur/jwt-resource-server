package org.entur.jwt.spring.properties.jwk;

/**
 * What the decoded JWT cache does with new JWTs once it has reached its target size.
 */
public enum JwtDecoderCacheMode {

    /**
     * Do not cache new JWTs until cached JWTs are removed (i.e. by the cleanup, once they are no longer valid).
     */
    FIXED,

    /**
     * Make room for new JWTs by evicting the JWTs which were cached first (first in, first out).
     */
    FIFO,

    /**
     * Make room for new JWTs by evicting the least recently used JWTs.
     */
    LRU
}
