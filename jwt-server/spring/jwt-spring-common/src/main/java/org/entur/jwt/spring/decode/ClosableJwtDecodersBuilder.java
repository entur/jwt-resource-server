package org.entur.jwt.spring.decode;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * Builds a per-issuer {@link JwtDecoder} map, wrapped in a {@link ClosableJwtDecoders} so that
 * decoders holding resources can be closed by Spring when the context shuts down.
 *
 */

public class ClosableJwtDecodersBuilder {

    private List<OAuth2TokenValidator<Jwt>> jwtValidators;
    private Map<String, JWKSource> jwkSources;

    public ClosableJwtDecodersBuilder withJwkSources(Map<String, JWKSource> jwkSources) {
        this.jwkSources = jwkSources;
        return this;
    }

    public ClosableJwtDecodersBuilder withJwtValidators(List<OAuth2TokenValidator<Jwt>> jwtValidators) {
        this.jwtValidators = jwtValidators;
        return this;
    }

    /**
     * Build the per-issuer {@link JwtDecoder}s, wrapped so that Spring can close any underlying
     * resources on context shutdown.
     */
    public ClosableJwtDecoders build() {
        Map<String, JwtDecoder> map = HashMap.newHashMap(jwkSources.size() * 4);

        for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {
            JWKSource jwkSource = entry.getValue();

            DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.Family.SIGNATURE, jwkSource);
            jwtProcessor.setJWSKeySelector(keySelector);
            // the claims (including expiry) are validated by the JWT validators, so disable the Nimbus verifier,
            // which would otherwise limit the leeway to its own (one minute) clock skew
            jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
            });

            NimbusJwtDecoder nimbusJwtDecoder = new NimbusJwtDecoder(jwtProcessor);
            nimbusJwtDecoder.setJwtValidator(JwtDecoderValidators.create(entry.getKey(), jwtValidators));

            map.put(entry.getKey(), nimbusJwtDecoder);
        }

        return new ClosableJwtDecoders(map);
    }
}
