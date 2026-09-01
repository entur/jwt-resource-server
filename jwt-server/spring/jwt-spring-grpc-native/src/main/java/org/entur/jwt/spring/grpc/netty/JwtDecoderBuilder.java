package org.entur.jwt.spring.grpc.netty;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.entur.jwt.spring.actuate.ListEventListener;
import org.entur.jwt.spring.cache.DecodedJwtCacheJwtDecoder;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapperDecider;
import org.entur.jwt.spring.properties.jwk.JwtDecoderCacheProperties;
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

public class JwtDecoderBuilder {

    private List<OAuth2TokenValidator<Jwt>> jwtValidators;
    private Map<String, JWKSource> jwkSources;
    private Map<String, ListEventListener> jwkEventListeners;
    private Map<String, JwtDecoderCacheProperties> decodedJwtCacheIssuers;
    private boolean mapHeaderToIssuer;
    private JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper;
    private JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider;

    public JwtDecoderBuilder withJwkEventListeners(Map<String, ListEventListener> jwkEventListeners) {
        this.jwkEventListeners = jwkEventListeners;
        return this;
    }

    public JwtDecoderBuilder withJwkSources(Map<String, JWKSource> jwkSources) {
        this.jwkSources = jwkSources;
        return this;
    }

    public JwtDecoderBuilder withJwtValidators(List<OAuth2TokenValidator<Jwt>> jwtValidators) {
        this.jwtValidators = jwtValidators;
        return this;
    }

    public JwtDecoderBuilder withDecodedJwtCacheIssuers(Map<String, JwtDecoderCacheProperties> decodedJwtCacheIssuers) {
        this.decodedJwtCacheIssuers = decodedJwtCacheIssuers;
        return this;
    }

    public JwtDecoderBuilder withMapHeaderToIssuer(boolean mapHeaderToIssuer) {
        this.mapHeaderToIssuer = mapHeaderToIssuer;
        return this;
    }

    public JwtDecoderBuilder withJwtHeaderToIssuerMapper(JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper) {
        this.jwtHeaderToIssuerMapper = jwtHeaderToIssuerMapper;
        return this;
    }

    public JwtDecoderBuilder withJwtHeaderToIssuerMapperDecider(JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider) {
        this.jwtHeaderToIssuerMapperDecider = jwtHeaderToIssuerMapperDecider;
        return this;
    }

    public JwtDecoder build() {
        Map<String, JwtDecoder> map = new HashMap<>(jwkSources.size() * 4);

        for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {
            JWKSource jwkSource = entry.getValue();

            DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.Family.SIGNATURE, jwkSource);
            jwtProcessor.setJWSKeySelector(keySelector);

            NimbusJwtDecoder nimbusJwtDecoder = new NimbusJwtDecoder(jwtProcessor);
            DelegatingOAuth2TokenValidator<Jwt> validators = getJwtValidators(entry.getKey());
            nimbusJwtDecoder.setJwtValidator(validators);

            JwtDecoder decoder = nimbusJwtDecoder;

            if(decodedJwtCacheIssuers != null) {
                JwtDecoderCacheProperties cacheProperties = decodedJwtCacheIssuers.get(entry.getKey());
                if(cacheProperties != null) {
                    ListEventListener eventListener = jwkEventListeners.get(entry.getKey());
                    if(eventListener != null) {
                        DecodedJwtCacheJwtDecoder cachedDecoder = new DecodedJwtCacheJwtDecoder(nimbusJwtDecoder, validators, cacheProperties.getCleanupInterval() * 1000, cacheProperties.getMaxSize());
                        cachedDecoder.scheduleCleanup();
                        eventListener.addEventListener(cachedDecoder);
                        decoder = cachedDecoder;
                    }
                }
            }

            map.put(entry.getKey(), decoder);
        }

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

    private DelegatingOAuth2TokenValidator<Jwt> getJwtValidators(String issuer) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtIssuerValidator(issuer));
        validators.addAll(jwtValidators);
        return new DelegatingOAuth2TokenValidator<>(validators);
    }
}
