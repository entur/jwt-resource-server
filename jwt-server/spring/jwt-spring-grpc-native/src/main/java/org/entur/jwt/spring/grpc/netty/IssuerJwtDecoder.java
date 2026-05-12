package org.entur.jwt.spring.grpc.netty;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import java.io.Closeable;
import java.io.IOException;
import java.text.ParseException;
import java.util.Map;

/**
 *
 * Multi-issuer JWT decoder.
 *
 */

public class IssuerJwtDecoder implements JwtDecoder, Closeable {

    private static final String DECODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to decode the Jwt: %s";

    public static JwtDecoderBuilder newBuilder() {
        return new JwtDecoderBuilder();
    }

    protected final Map<String, JwtDecoder> decoders;

    public IssuerJwtDecoder(Map<String, JwtDecoder> decoders) {
        this.decoders = decoders;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        // note to self: there is two jwt classes, Jwt and JWT
        try {
            JWT parse = JWTParser.parse(token);

            JwtDecoder decoder = decoders.get(parse.getJWTClaimsSet().getIssuer());
            if (decoder != null) {
                return decoder.decode(token);
            }

            throw new BadJwtException("Unknown issuer " + parse.getJWTClaimsSet().getIssuer());
        } catch (ParseException ex) {
            throw new InvalidBearerTokenException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
        }
    }

    @Override
    public void close() throws IOException {
        for (Map.Entry<String, JwtDecoder> entry : decoders.entrySet()) {
            JwtDecoder value = entry.getValue();

            if(value instanceof Closeable c) {
                IOUtils.closeQuietly(c);
            }
        }

    }
}
