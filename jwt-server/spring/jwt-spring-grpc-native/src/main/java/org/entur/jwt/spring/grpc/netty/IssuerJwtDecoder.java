package org.entur.jwt.spring.grpc.netty;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.actuate.ListEventListener;
import org.entur.jwt.spring.issuer.JwkHeaderToIssuerEventListener;
import org.entur.jwt.spring.issuer.JwkHeaderToIssuerEventListeners;
import org.entur.jwt.spring.issuer.JwtHeaderToIssuerMapper;
import org.jspecify.annotations.NonNull;
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

        public JwtDecoder build() {
            Map<String, JWKSource> jwkSources = jwkSourceMap.getJwkSources();

            if(jwkSources.size() == 1) {
                String issuer = jwkSources.keySet().iterator().next();
                JWKSource jwkSource = jwkSources.get(issuer);

                return getNimbusJwtDecoder(issuer, jwkSource);
            }

            // create multi-tenant decoder which attempts to avoid parsing the whole
            // JWT to map the JWT to the correct decoder
            Map<String, ListEventListener> jwkEventListeners = jwkSourceMap.getJwkEventListeners();

            JwtHeaderToIssuerMapper mapper =  new JwtHeaderToIssuerMapper();
            JwkHeaderToIssuerEventListeners listeners = new JwkHeaderToIssuerEventListeners(jwkSources.size(), mapper);

            Map<String, JwtDecoder> map = new HashMap<>(jwkSources.size() * 4);

            for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {
                JWKSource jwkSource = entry.getValue();
                String issuer = entry.getKey();

                ListEventListener listEventListener = jwkEventListeners.get(issuer);
                listEventListener.addEventListener(new JwkHeaderToIssuerEventListener(issuer, listeners));

                NimbusJwtDecoder nimbusJwtDecoder = getNimbusJwtDecoder(issuer, jwkSource);

                map.put(issuer, nimbusJwtDecoder);
            }

            return new IssuerJwtDecoder(map, mapper);
        }

        private @NonNull NimbusJwtDecoder getNimbusJwtDecoder(String issuer, JWKSource jwkSource) {
            DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.Family.SIGNATURE, jwkSource);
            jwtProcessor.setJWSKeySelector(keySelector);

            NimbusJwtDecoder nimbusJwtDecoder = new NimbusJwtDecoder(jwtProcessor);
            nimbusJwtDecoder.setJwtValidator(getJwtValidators(issuer));
            return nimbusJwtDecoder;
        }

        private DelegatingOAuth2TokenValidator<Jwt> getJwtValidators(String issuer) {
            List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
            validators.add(new JwtIssuerValidator(issuer));
            validators.addAll(jwtValidators);
            DelegatingOAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(validators);
            return validator;
        }
    }

    protected final Map<String, JwtDecoder> decoders;
    private final JwtHeaderToIssuerMapper mapper;

    public IssuerJwtDecoder(Map<String, JwtDecoder> decoders, JwtHeaderToIssuerMapper mapper) {
        this.decoders = decoders;
        this.mapper = mapper;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        // note to self: there is two jwt classes, Jwt and JWT
        try {
            String issuer = mapper.get(token);
            if(issuer != null) {
                // fast path
                JwtDecoder decoder = decoders.get(issuer);
                if (decoder != null) {
                    return decoder.decode(token);
                }
            } else {
                // slow path
                JWT parse = JWTParser.parse(token);

                issuer = parse.getJWTClaimsSet().getIssuer();

                JwtDecoder decoder = decoders.get(issuer);
                if (decoder != null) {
                    Jwt decode = decoder.decode(token);

                    if(mapper.isEnabled(issuer) && hasKid(decode)) {
                        // cache this jwt header
                        mapper.add(issuer, token);
                    }

                    return decode;
                }
            }

            throw new BadJwtException("Unknown issuer " + issuer);
        } catch (ParseException ex) {
            throw new InvalidBearerTokenException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
        }
    }

    private static boolean hasKid(Jwt decode) {
        return decode.getHeaders().get("kid") != null;
    }

    public JwtHeaderToIssuerMapper getMapper() {
        return mapper;
    }
}
