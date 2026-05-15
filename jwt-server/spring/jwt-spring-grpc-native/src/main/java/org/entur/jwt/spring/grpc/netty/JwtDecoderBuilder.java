package org.entur.jwt.spring.grpc.netty;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.actuate.ListEventListener;
import org.entur.jwt.spring.cache.DecodedJwtCacheJwtDecoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class JwtDecoderBuilder {

    private List<OAuth2TokenValidator<Jwt>> jwtValidators;
    private Map<String, JWKSource> jwkSources;
    private Map<String, ListEventListener> jwkEventListeners;
    private Set<String> decodedJwtCacheIssuers;

    public JwtDecoderBuilder withJwkEventListeners(Map<String, ListEventListener> jwkEventListeners) {
        this.jwkEventListeners = jwkEventListeners;
        return this;
    }

    public JwtDecoderBuilder withJwkSources(Map<String, JWKSource> jwkSources) {
        this.jwkSources = jwkSources;
        return this;
    }

    public JwtDecoderBuilder withDecodedJwtCacheIssuers(Set<String> decodedJwtCacheIssuers) {
        this.decodedJwtCacheIssuers = decodedJwtCacheIssuers;
        return this;
    }

    public JwtDecoderBuilder withJwtValidators(List<OAuth2TokenValidator<Jwt>> jwtValidators) {
        this.jwtValidators = jwtValidators;
        return this;
    }

    public JwtDecoder build() {

        if(decodedJwtCacheIssuers.isEmpty()) {
            if(jwkSources.size() == 1) {
                Map.Entry<String, JWKSource> next = jwkSources.entrySet().iterator().next();
                return createSingleDecoder(next.getKey(), next.getValue());
            } else {
                return createMultiDecoder();
            }
        } else {
            if(jwkSources.size() == 1) {
                Map.Entry<String, JWKSource> next = jwkSources.entrySet().iterator().next();
                return createSingleCachedDecoder(next.getKey(), next.getValue());
            } else {
                return createMultiCachedDecoder();
            }
        }
    }

    private JwtDecoder createMultiCachedDecoder() {
        Map<String, JwtDecoder> map = new HashMap<>(jwkSources.size() * 4);

        for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {
            JWKSource jwkSource = entry.getValue();
            ListEventListener listEventListener = jwkEventListeners.get(entry.getKey());

            DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.Family.SIGNATURE, jwkSource);
            jwtProcessor.setJWSKeySelector(keySelector);

            NimbusJwtDecoder nimbusJwtDecoder = new NimbusJwtDecoder(jwtProcessor);
            nimbusJwtDecoder.setJwtValidator(getJwtValidators(entry.getKey()));

            JwtDecoder jwtDecoder;
            if(decodedJwtCacheIssuers.contains(entry.getKey())) {
                DecodedJwtCacheJwtDecoder decodedJwtCacheJwtDecoder = new DecodedJwtCacheJwtDecoder(nimbusJwtDecoder, getJwtValidators(entry.getKey()), 60_000);
                listEventListener.addEventListener(decodedJwtCacheJwtDecoder);
                jwtDecoder = decodedJwtCacheJwtDecoder;
            } else {
                jwtDecoder =  nimbusJwtDecoder;
            }

            map.put(entry.getKey(), jwtDecoder);
        }

        return new IssuerJwtDecoder(map);
    }

    public IssuerJwtDecoder createMultiDecoder() {
        Map<String, JwtDecoder> map = new HashMap<>(jwkSources.size() * 4);

        for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {
            JWKSource jwkSource = entry.getValue();


            DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.Family.SIGNATURE, jwkSource);
            jwtProcessor.setJWSKeySelector(keySelector);

            NimbusJwtDecoder nimbusJwtDecoder = new NimbusJwtDecoder(jwtProcessor);

            // issur check is implicit
            DelegatingOAuth2TokenValidator<Jwt> validatorsWithoutIssuerCheck = new DelegatingOAuth2TokenValidator<>(jwtValidators);
            nimbusJwtDecoder.setJwtValidator(validatorsWithoutIssuerCheck);

            map.put(entry.getKey(), nimbusJwtDecoder);
        }

        return new IssuerJwtDecoder(map);
    }

    private JwtDecoder createSingleCachedDecoder(String key, JWKSource value) {
        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.Family.SIGNATURE, value);
        jwtProcessor.setJWSKeySelector(keySelector);

        NimbusJwtDecoder nimbusJwtDecoder = new NimbusJwtDecoder(jwtProcessor);
        DelegatingOAuth2TokenValidator<Jwt> validatorsWithIssuerCheck = getJwtValidators(key);
        nimbusJwtDecoder.setJwtValidator(validatorsWithIssuerCheck);

        if(decodedJwtCacheIssuers.contains(key)) {
            DelegatingOAuth2TokenValidator<Jwt> validatorsWithoutIssuerCheck = new DelegatingOAuth2TokenValidator<>(jwtValidators);
            DecodedJwtCacheJwtDecoder decodedJwtCacheJwtDecoder = new DecodedJwtCacheJwtDecoder(nimbusJwtDecoder, validatorsWithoutIssuerCheck, 60_000);

            ListEventListener listEventListener = jwkEventListeners.get(key);
            listEventListener.addEventListener(decodedJwtCacheJwtDecoder);
            return decodedJwtCacheJwtDecoder;
        }
        return nimbusJwtDecoder;
    }

    private JwtDecoder createSingleDecoder(String key, JWKSource jwkSource) {
        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.Family.SIGNATURE, jwkSource);
        jwtProcessor.setJWSKeySelector(keySelector);

        DelegatingOAuth2TokenValidator<Jwt> validatorsWithIssuerCheck = getJwtValidators(key);

        NimbusJwtDecoder nimbusJwtDecoder = new NimbusJwtDecoder(jwtProcessor);
        nimbusJwtDecoder.setJwtValidator(validatorsWithIssuerCheck);
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
