package org.entur.jwt.spring.decode;

import org.springframework.security.oauth2.jwt.Jwt;

/**
 *
 * Accept mapping if the header has a non-empty kid
 *
 */

public class DefaultJwtHeaderToIssuerMapperDecider implements JwtHeaderToIssuerMapperDecider {

    @Override
    public boolean apply(Jwt jwt) {
        Object kid = jwt.getHeaders().get("kid");
        if(kid != null) {
            if(kid instanceof String s) {
                return !s.isEmpty();
            }
        }
        return false;
    }
}
