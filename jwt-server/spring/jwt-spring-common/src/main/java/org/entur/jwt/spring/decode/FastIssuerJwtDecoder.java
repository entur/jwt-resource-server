package org.entur.jwt.spring.decode;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.text.ParseException;
import java.util.Map;

/**
 *
 * Multi-issuer JWT decoder with a JWT header to issuer cache: tokens with a known header are decoded by the decoder
 * of the issuer the header is mapped to, without first parsing the token to read its issuer (fast path).
 * <br><br>
 * Issuers which share a signing key and key id produce identical headers. So if a token fails to decode on the fast path,
 * and its issuer claim names another issuer, the token is decoded by its issuer claim like without the cache (slow path);
 * the header is then no longer mapped (see {@link JwtHeaderToIssuerMapper}).
 *
 */

public class FastIssuerJwtDecoder extends IssuerJwtDecoder {

    protected final JwtHeaderToIssuerMapper mapper;
    protected final JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider;

    public FastIssuerJwtDecoder(Map<String, JwtDecoder> decoders, JwtHeaderToIssuerMapper mapper, JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider) {
        super(decoders);
        this.mapper = mapper;
        this.jwtHeaderToIssuerMapperDecider = jwtHeaderToIssuerMapperDecider;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        // note to self: there is two jwt classes, Jwt and JWT
        String issuer = mapper.get(token);
        if(issuer != null) {
            // fast path
            JwtDecoder decoder = decoders.get(issuer);
            if (decoder == null) {
                throw new BadJwtException("Unknown issuer " + issuer);
            }
            try {
                return decoder.decode(token);
            } catch (JwtException e) {
                // the header might also be used by another issuer, if so decode as usual (slow path).
                // Otherwise do not decode again, i.e. for an expired token.
                if(!isOtherIssuer(token, issuer)) {
                    throw e;
                }
            }
        }
        // slow path
        Jwt jwt = super.decode(token);

        issuer = jwt.getClaim("iss");
        if(issuer != null) {

            if(jwtHeaderToIssuerMapperDecider.apply(jwt)) {
                // use this header as a cache key
                mapper.add(issuer, token);
            }
        }
        return jwt;
    }

    /**
     * @param token the raw JWT token string
     * @param issuer the issuer the token's header is mapped to
     * @return true if the token's (not yet verified) issuer claim names another issuer
     */
    protected static boolean isOtherIssuer(String token, String issuer) {
        try {
            JWTClaimsSet claims = JWTParser.parse(token).getJWTClaimsSet();
            return claims != null && claims.getIssuer() != null && !claims.getIssuer().equals(issuer);
        } catch (ParseException e) {
            // not a JWT
            return false;
        }
    }

    public JwtHeaderToIssuerMapper getMapper() {
        return mapper;
    }

}
