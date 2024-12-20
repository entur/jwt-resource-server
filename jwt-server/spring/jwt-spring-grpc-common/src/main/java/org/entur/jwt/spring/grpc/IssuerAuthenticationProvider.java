package org.entur.jwt.spring.grpc;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.entur.jwt.spring.EnrichedJwtGrantedAuthoritiesConverter;
import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.JwtAuthorityEnricher;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class IssuerAuthenticationProvider implements AuthenticationProvider {

    private static final String DECODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to decode the Jwt: %s";

    public static Builder newBuilder() {
        return new Builder();
    }

    public static class Builder {

        private List<JwtAuthorityEnricher> jwtAuthorityEnrichers;
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

        public Builder withJwtAuthorityEnrichers(List<JwtAuthorityEnricher> jwtAuthorityEnrichers) {
            this.jwtAuthorityEnrichers = jwtAuthorityEnrichers;
            return this;
        }

        public IssuerAuthenticationProvider build() {
            Map<String, JWKSource> jwkSources = jwkSourceMap.getJwkSources();

            Map<String, AuthenticationProvider> map = new HashMap<>(jwkSources.size() * 4);

            for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {
                JWKSource jwkSource = entry.getValue();

                DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
                JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.Family.SIGNATURE, jwkSource);
                jwtProcessor.setJWSKeySelector(keySelector);

                NimbusJwtDecoder nimbusJwtDecoder = new NimbusJwtDecoder(jwtProcessor);
                nimbusJwtDecoder.setJwtValidator(getJwtValidators(entry.getKey()));

                JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();

                jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new EnrichedJwtGrantedAuthoritiesConverter(jwtAuthorityEnrichers));

                JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(nimbusJwtDecoder);
                authenticationProvider.setJwtAuthenticationConverter(jwtAuthenticationConverter);

                map.put(entry.getKey(), authenticationProvider);
            }

           return new IssuerAuthenticationProvider(map);
        }

        private DelegatingOAuth2TokenValidator<Jwt> getJwtValidators(String issuer) {
            List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
            validators.add(new JwtIssuerValidator(issuer)); // this check is implicit, but lets add it regardless
            validators.addAll(jwtValidators);
            DelegatingOAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(validators);
            return validator;
        }
    }

    private final Map<String, AuthenticationProvider> map;

    public IssuerAuthenticationProvider(Map<String, AuthenticationProvider> map) {
        this.map = map;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        BearerTokenAuthenticationToken bearerTokenAuthenticationToken = (BearerTokenAuthenticationToken) authentication;

        // note to self: there is two jwt classes, Jwt and JWT
        try {
            JWT parse = JWTParser.parse(bearerTokenAuthenticationToken.getToken());

            AuthenticationProvider authenticationProvider = map.get(parse.getJWTClaimsSet().getIssuer());
            if (authenticationProvider != null) {
                return authenticationProvider.authenticate(bearerTokenAuthenticationToken);
            }

            throw new BadCredentialsException("");
        } catch (ParseException ex) {
            throw new InvalidBearerTokenException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // note: turns out there is two BearerTokenAuthenticationToken (the one deprecated extends the other)

        return org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
