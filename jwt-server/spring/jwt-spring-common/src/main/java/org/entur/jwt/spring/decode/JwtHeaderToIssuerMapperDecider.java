package org.entur.jwt.spring.decode;

import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Decide that the header can be used to map the issuser. Typically check for kid or any unquie property from
 * https://www.rfc-editor.org/info/rfc7515/#section-4.1.4
 *
 */

public interface JwtHeaderToIssuerMapperDecider {

    /**
     * Check that the header can be used to map issuer (i.e. is cachable).
     *
     * @param jwt decoded JWT
     * @return true if cachable
     */

    boolean apply(Jwt jwt);

}
