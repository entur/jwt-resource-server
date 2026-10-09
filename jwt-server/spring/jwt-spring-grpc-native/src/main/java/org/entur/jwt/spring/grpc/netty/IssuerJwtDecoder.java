package org.entur.jwt.spring.grpc.netty;

import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.decode.ClosableJwtDecoders;
import org.entur.jwt.spring.decode.ClosableJwtDecodersBuilder;
import org.entur.jwt.spring.decode.IssuerJwtDecoderFactory;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapperDecider;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.List;
import java.util.Map;

/**
 *
 * Multi-issuer JWT decoder.
 *
 * @deprecated moved to {@link org.entur.jwt.spring.decode.IssuerJwtDecoder}. The per-issuer decoders are the
 * {@link ClosableJwtDecoders} bean (see {@link ClosableJwtDecodersBuilder} and {@link IssuerJwtDecoderFactory}),
 * which is shared with the web module; this class and its builder build their own decoders. To be removed in the next major version.
 */
@Deprecated
public class IssuerJwtDecoder extends org.entur.jwt.spring.decode.IssuerJwtDecoder {

    public static Builder newBuilder() {
        return new Builder();
    }

    @Deprecated
    public static class Builder {

        private List<OAuth2TokenValidator<Jwt>> jwtValidators;
        private JwkSourceMap jwkSourceMap;
        private boolean mapHeaderToIssuer;
        private JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper;
        private JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider;

        public Builder withJwtHeaderToIssuerMapperDeciderProvider(JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider) {
            this.jwtHeaderToIssuerMapperDecider = jwtHeaderToIssuerMapperDecider;
            return this;
        }

        public Builder withJwkSourceMap(JwkSourceMap jwkSourceMap) {
            this.jwkSourceMap = jwkSourceMap;
            return this;
        }

        public Builder withJwtValidators(List<OAuth2TokenValidator<Jwt>> jwtValidators) {
            this.jwtValidators = jwtValidators;
            return this;
        }

        public Builder withJwtHeaderToIssuerMapper(JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper) {
            this.jwtHeaderToIssuerMapper = jwtHeaderToIssuerMapper;
            return this;
        }

        public Builder withMapHeaderToIssuer(boolean mapHeaderToIssuer) {
            this.mapHeaderToIssuer = mapHeaderToIssuer;
            return this;
        }

        /**
         * @return as before: the only decoder if there is a single issuer, otherwise a (fast) issuer decoder of this package
         */
        public JwtDecoder build() {
            // the decoders are not shared with other modules (and have nothing to close)
            ClosableJwtDecoders closableJwtDecoders = new ClosableJwtDecodersBuilder()
                    .withJwkSources(jwkSourceMap.getJwkSources())
                    .withJwtValidators(jwtValidators)
                    .build();
            Map<String, JwtDecoder> map = closableJwtDecoders.getJwtDecoders();

            if(map.size() == 1) {
                return map.values().iterator().next();
            }

            if(mapHeaderToIssuer) {
                if(jwtHeaderToIssuerMapper == null) {
                    throw new IllegalStateException("JwtHeaderToIssuerMapper bean is required when 'entur.jwt.decode.header.map-to-issuer.enabled=true' but was not found in the application context");
                }
                if(jwtHeaderToIssuerMapperDecider == null) {
                    throw new IllegalStateException("jwtHeaderToIssuerMapperDecider bean is required when 'entur.jwt.decode.header.map-to-issuer.enabled=true' but was not found in the application context");
                }
                return new FastIssuerJwtDecoder(map, jwtHeaderToIssuerMapper, jwtHeaderToIssuerMapperDecider);
            }

            return new IssuerJwtDecoder(map);
        }
    }

    public IssuerJwtDecoder(Map<String, JwtDecoder> decoders) {
        super(decoders);
    }
}
