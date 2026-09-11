package org.entur.jwt.spring.decode;

import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.Map;

/**
 *
 * Wrapper which allows underlying resource to be closed by spring
 *
 */

public class ClosableJwtDecoders implements AutoCloseable {

    private final Map<String, JwtDecoder> decoders;

    public ClosableJwtDecoders(Map<String, JwtDecoder> decoders) {
        this.decoders = decoders;
    }

    @Override
    public void close() throws Exception {
        for (Map.Entry<String, JwtDecoder> stringJwtDecoderEntry : decoders.entrySet()) {
            JwtDecoder jwtDecoder = stringJwtDecoderEntry.getValue();
            if (jwtDecoder instanceof AutoCloseable c) {
                c.close();
            }
        }
    }

    public Map<String, JwtDecoder> getJwtDecoders() {
        return decoders;
    }
}
