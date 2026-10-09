package org.entur.jwt.spring.decode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger LOGGER = LoggerFactory.getLogger(ClosableJwtDecoders.class);

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

    /**
     * Close all resources and decoders. Never throws: if any of them fails, it is logged and the rest are still closed.
     */
    @Override
    public void close() {
        for (AutoCloseable resource : resources) {
            close(resource, "resource");
        }
        for (Map.Entry<String, JwtDecoder> stringJwtDecoderEntry : decoders.entrySet()) {
            JwtDecoder jwtDecoder = stringJwtDecoderEntry.getValue();
            if (jwtDecoder instanceof AutoCloseable c) {
                close(c, "decoder for issuer " + stringJwtDecoderEntry.getKey());
            }
        }
    }

    private static void close(AutoCloseable closeable, String description) {
        try {
            closeable.close();
        } catch (Exception e) {
            LOGGER.warn("Problem closing {}", description, e);
        }
    }

    public Map<String, JwtDecoder> getJwtDecoders() {
        return decoders;
    }
}
