package org.entur.jwt.spring.grpc.netty;

import org.entur.jwt.spring.decode.ClosableJwtDecoders;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 *
 * Holds the {@link JwtDecoder} used by the gRPC interceptor, and closes the underlying (caching) decoders
 * when the Spring context shuts down.
 * <br><br>
 * Intentionally not a {@link JwtDecoder} itself: exposing a {@link JwtDecoder} bean activates Spring Boot's
 * default resource server {@code SecurityFilterChain}, which would then require a JWT for all HTTP endpoints
 * (including actuator health probes).
 *
 */

public class GrpcJwtDecoderHolder implements AutoCloseable {

    private final JwtDecoder jwtDecoder;
    private final ClosableJwtDecoders closableJwtDecoders;

    public GrpcJwtDecoderHolder(JwtDecoder jwtDecoder, ClosableJwtDecoders closableJwtDecoders) {
        this.jwtDecoder = jwtDecoder;
        this.closableJwtDecoders = closableJwtDecoders;
    }

    public JwtDecoder getJwtDecoder() {
        return jwtDecoder;
    }

    @Override
    public void close() throws Exception {
        closableJwtDecoders.close();
    }
}
