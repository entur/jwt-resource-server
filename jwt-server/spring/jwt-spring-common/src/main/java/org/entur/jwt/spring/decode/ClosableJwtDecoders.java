package org.entur.jwt.spring.decode;

import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 *
 * Wrapper which allows underlying resource to be closed by spring
 *
 */

public class ClosableJwtDecoders implements AutoCloseable {

    private final Map<String, JwtDecoder> decoders;
    // closed before the decoders, i.e. JWK event listener registrations
    private final List<AutoCloseable> resources;

    public ClosableJwtDecoders(Map<String, JwtDecoder> decoders) {
        this(decoders, Collections.emptyList());
    }

    /**
     * @param decoders per-issuer decoders
     * @param resources additional resources to close (before the decoders), i.e. JWK event listener registrations
     */
    public ClosableJwtDecoders(Map<String, JwtDecoder> decoders, List<AutoCloseable> resources) {
        this.decoders = decoders;
        this.resources = resources;
    }

    @Override
    public void close() throws Exception {
        for (AutoCloseable resource : resources) {
            resource.close();
        }
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
