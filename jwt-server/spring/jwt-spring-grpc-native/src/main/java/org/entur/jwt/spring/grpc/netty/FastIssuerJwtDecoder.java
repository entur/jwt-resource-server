package org.entur.jwt.spring.grpc.netty;

import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapperDecider;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.Map;

/**
 *
 * Multi-issuer JWT decoder with a JWT header to issuer cache.
 *
 * @deprecated moved to {@link org.entur.jwt.spring.decode.FastIssuerJwtDecoder}. To be removed in the next major version.
 */
@Deprecated
public class FastIssuerJwtDecoder extends org.entur.jwt.spring.decode.FastIssuerJwtDecoder {

    public FastIssuerJwtDecoder(Map<String, JwtDecoder> decoders, JwtHeaderToIssuerMapper mapper, JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider) {
        super(decoders, mapper, jwtHeaderToIssuerMapperDecider);
    }
}
