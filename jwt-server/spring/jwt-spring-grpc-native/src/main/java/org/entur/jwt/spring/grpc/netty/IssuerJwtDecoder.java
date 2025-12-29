package org.entur.jwt.spring.grpc.netty;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.entur.jwt.spring.JwkSourceMap;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * Multi-issuer JWT decoder.
 *
 */

public class IssuerJwtDecoder implements JwtDecoder {

    private static final String DECODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to decode the Jwt: %s";

    public static Builder newBuilder() {
        return new Builder();
    }

    public static class Builder {

        private List<OAuth2TokenValidator<Jwt>> jwtValidators;
        private JwkSourceMap jwkSourceMap;

        public Builder withJwkSourceMap(JwkSourceMap jwkSourceMap) {
            this.jwkSourceMap = jwkSourceMap;
            return this;
        }

        public Builder withJwtValidators(List<OAuth2TokenValidator<Jwt>> jwtValidators) {
            this.jwtValidators = jwtValidators;
            return this;
        }

        public IssuerJwtDecoder build() {
            Map<String, JWKSource> jwkSources = jwkSourceMap.getJwkSources();

            Map<String, JwtDecoder> map = new HashMap<>(jwkSources.size() * 4);

            for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {
                JWKSource jwkSource = entry.getValue();

                DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
                JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.Family.SIGNATURE, jwkSource);
                jwtProcessor.setJWSKeySelector(keySelector);

                NimbusJwtDecoder nimbusJwtDecoder = new NimbusJwtDecoder(jwtProcessor);
                nimbusJwtDecoder.setJwtValidator(getJwtValidators(entry.getKey()));

                map.put(entry.getKey(), nimbusJwtDecoder);
            }

            return new IssuerJwtDecoder(map);
        }

        private DelegatingOAuth2TokenValidator<Jwt> getJwtValidators(String issuer) {
            List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
            validators.add(new JwtIssuerValidator(issuer)); // this check is implicit, but lets add it regardless
            validators.addAll(jwtValidators);
            DelegatingOAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(validators);
            return validator;
        }
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
}
