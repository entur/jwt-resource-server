package org.entur.jwt.spring.grpc.netty;

import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 *
 * Holds the {@link JwtDecoder} used by the gRPC interceptor. The underlying per-issuer decoders are the shared
 * {@link org.entur.jwt.spring.decode.ClosableJwtDecoders} bean, which is closed by Spring.
 * <br><br>
 * Intentionally not a {@link JwtDecoder} itself: exposing a {@link JwtDecoder} bean activates Spring Boot's
 * default resource server {@code SecurityFilterChain}, which would then require a JWT for all HTTP endpoints
 * (including actuator health probes).
 *
 */

public class GrpcJwtDecoderHolder {

    private final JwtDecoder jwtDecoder;

    public GrpcJwtDecoderHolder(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    public JwtDecoder getJwtDecoder() {
        return jwtDecoder;
    }
}
