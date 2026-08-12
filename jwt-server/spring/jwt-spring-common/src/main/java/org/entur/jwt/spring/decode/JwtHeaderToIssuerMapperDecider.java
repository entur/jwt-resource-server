package org.entur.jwt.spring.decode;

import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Decide whether the JWT header can be used to map the issuer. Typically checks for "kid"
 * or another unique property from RFC 7515 section 4.1.4:
 * https://www.rfc-editor.org/info/rfc7515/#section-4.1.4
 */

public interface JwtHeaderToIssuerMapperDecider {

    /**
     * Check that the header can be used to map issuer (i.e. is cacheable).
     *
     * @param jwt decoded JWT
     * @return true if cacheable
     */

    boolean apply(Jwt jwt);

}
