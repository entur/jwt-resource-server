package org.entur.jwt.spring.decode;

import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.Map;

/**
 *
 * Creates a single {@link JwtDecoder} for the per-issuer decoders of a {@link ClosableJwtDecoders}.
 *
 */

public class IssuerJwtDecoderFactory {

    private IssuerJwtDecoderFactory() {
    }

    /**
     * @param decoders per-issuer decoders
     * @param mapHeaderToIssuer whether to map JWT headers to issuers, see {@link FastIssuerJwtDecoder}
     * @param jwtHeaderToIssuerMapper required if mapping headers to issuers
     * @param jwtHeaderToIssuerMapperDecider required if mapping headers to issuers
     * @return the only decoder if there is a single issuer, otherwise a decoder which picks the decoder by issuer
     */
    public static JwtDecoder create(Map<String, JwtDecoder> decoders, boolean mapHeaderToIssuer, JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper, JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider) {
        if (decoders.size() == 1) {
            // if there is only one decoder, we can return it directly without the overhead of the FastIssuerJwtDecoder / IssuerJwtDecoder
            return decoders.values().iterator().next();
        }

        if (mapHeaderToIssuer) {
            if (jwtHeaderToIssuerMapper == null) {
                throw new IllegalStateException("JwtHeaderToIssuerMapper bean is required when 'entur.jwt.decode.header.map-to-issuer.enabled=true' but was not found in the application context");
            }
            if (jwtHeaderToIssuerMapperDecider == null) {
                throw new IllegalStateException("JwtHeaderToIssuerMapperDecider bean is required when 'entur.jwt.decode.header.map-to-issuer.enabled=true' but was not found in the application context");
            }
            return new FastIssuerJwtDecoder(decoders, jwtHeaderToIssuerMapper, jwtHeaderToIssuerMapperDecider);
        }

        return new IssuerJwtDecoder(decoders);
    }
}
