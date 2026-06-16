package org.entur.jwt.spring.grpc.netty;

import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.util.Map;

public class FastIssuerJwtDecoder extends IssuerJwtDecoder {

    protected final JwtHeaderToIssuerMapper mapper;

    public FastIssuerJwtDecoder(Map<String, JwtDecoder> decoders, JwtHeaderToIssuerMapper mapper) {
        super(decoders);
        this.mapper = mapper;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        // note to self: there is two jwt classes, Jwt and JWT
        String issuer = mapper.get(token);
        if(issuer != null) {
            // fast path
            JwtDecoder decoder = decoders.get(issuer);
            if (decoder != null) {
                return decoder.decode(token);
            }
            throw new BadJwtException("Unknown issuer " + issuer);
        } else {
            // slow path
            Jwt jwt = super.decode(token);

            issuer = jwt.getClaim("iss");
            if(issuer != null) {
                // cache this jwt header
                mapper.add(issuer, token);

            }
            return jwt;
        }
    }

    public JwtHeaderToIssuerMapper getMapper() {
        return mapper;
    }

}
