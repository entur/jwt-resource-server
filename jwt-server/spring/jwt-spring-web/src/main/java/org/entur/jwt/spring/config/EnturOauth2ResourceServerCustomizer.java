package org.entur.jwt.spring.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.entur.jwt.spring.EnrichedJwtGrantedAuthoritiesConverter;
import org.entur.jwt.spring.JwtAuthorityEnricher;
import org.entur.jwt.spring.actuate.ListEventListener;
import org.entur.jwt.spring.cache.DecodedJwtCacheJwtDecoder;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapperDecider;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.entur.jwt.spring.properties.JwtDecodeProperties;
import org.entur.jwt.spring.properties.JwtHeaderDecodeProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class EnturOauth2ResourceServerCustomizer implements Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> {

    private static final Logger LOGGER = LoggerFactory.getLogger(EnturOauth2ResourceServerCustomizer.class);

    private final Map<String, JWKSource> jwkSources;
    private final List<JwtAuthorityEnricher> jwtAuthorityEnrichers;
    private final List<OAuth2TokenValidator<Jwt>> jwtValidators;
    private final JwtDecodeProperties properties;
    private final JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper;
    private final JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider;
    private final Map<String, ListEventListener> jwkEventListeners;
    private final Set<String> decodedJwtCacheIssuers;

    public EnturOauth2ResourceServerCustomizer(JwtDecodeProperties properties, Map<String, JWKSource> jwkSources, List<JwtAuthorityEnricher> jwtAuthorityEnrichers, List<OAuth2TokenValidator<Jwt>> jwtValidators) {
        this(properties, jwkSources, jwtAuthorityEnrichers, jwtValidators, null, null, Collections.emptyMap(), Collections.emptySet());
    }

    public EnturOauth2ResourceServerCustomizer(
            JwtDecodeProperties properties, Map<String, JWKSource> jwkSources,
            List<JwtAuthorityEnricher> jwtAuthorityEnrichers,
            List<OAuth2TokenValidator<Jwt>> jwtValidators,
            JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper,
            JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider
            ) {
        this(properties, jwkSources, jwtAuthorityEnrichers, jwtValidators, jwtHeaderToIssuerMapper, jwtHeaderToIssuerMapperDecider, Collections.emptyMap(), Collections.emptySet());
    }

    public EnturOauth2ResourceServerCustomizer(
            JwtDecodeProperties properties, Map<String, JWKSource> jwkSources,
            List<JwtAuthorityEnricher> jwtAuthorityEnrichers,
            List<OAuth2TokenValidator<Jwt>> jwtValidators,
            JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper,
            JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider,
            Map<String, ListEventListener> jwkEventListeners,
            Set<String> decodedJwtCacheIssuers
            ) {
        this.properties = properties;
        this.jwkSources = jwkSources;
        this.jwtAuthorityEnrichers = jwtAuthorityEnrichers;
        this.jwtValidators = jwtValidators;
        this.jwtHeaderToIssuerMapper = jwtHeaderToIssuerMapper;
        this.jwtHeaderToIssuerMapperDecider = jwtHeaderToIssuerMapperDecider;
        this.jwkEventListeners = jwkEventListeners;
        this.decodedJwtCacheIssuers = decodedJwtCacheIssuers;
    }

    @Override
    public void customize(OAuth2ResourceServerConfigurer<HttpSecurity> configurer) {

        if(LOGGER.isDebugEnabled()) LOGGER.debug("Customize {} issuers", jwkSources.size());

        Map<String, AuthenticationManager> map = new HashMap<>(); // thread safe for reading

        for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {
            JWKSource jwkSource = entry.getValue();

            DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.Family.SIGNATURE, jwkSource);
            jwtProcessor.setJWSKeySelector(keySelector);

            NimbusJwtDecoder nimbusJwtDecoder = new NimbusJwtDecoder(jwtProcessor);
            DelegatingOAuth2TokenValidator<Jwt> validators = getJwtValidators(entry.getKey());
            nimbusJwtDecoder.setJwtValidator(validators);

            JwtDecoder decoder = nimbusJwtDecoder;

            if(decodedJwtCacheIssuers.contains(entry.getKey())) {
                ListEventListener eventListener = jwkEventListeners.get(entry.getKey());
                if(eventListener != null) {
                    DecodedJwtCacheJwtDecoder cachedDecoder = new DecodedJwtCacheJwtDecoder(nimbusJwtDecoder, validators, 60_000);
                    cachedDecoder.scheduleCleanup();
                    eventListener.addEventListener(cachedDecoder);
                    decoder = cachedDecoder;
                }
            }

            JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
            jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new EnrichedJwtGrantedAuthoritiesConverter(jwtAuthorityEnrichers));

            JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(decoder);
            authenticationProvider.setJwtAuthenticationConverter(jwtAuthenticationConverter);

            map.put(entry.getKey(), authenticationProvider::authenticate);
        }

        if(map.size() == 1) {
            AuthenticationManager next = map.values().iterator().next();
            configurer.authenticationManagerResolver(request -> next);
        } else {
            AuthenticationManagerResolver<String> issuer = new IssuerAuthenticationManagerResolver(map);

            JwtHeaderDecodeProperties header = properties.getHeader();
            if(header.getMapToIssuer().isEnabled()) {
                if(jwtHeaderToIssuerMapper == null) {
                    throw new IllegalStateException("JwtHeaderToIssuerMapper bean is required when 'entur.jwt.decode.header.map-to-issuer.enabled=true' but was not found in the application context");
                }
                if(jwtHeaderToIssuerMapperDecider == null) {
                    throw new IllegalStateException("JwtHeaderToIssuerMapperDecider bean is required when 'entur.jwt.decode.header.map-to-issuer.enabled=true' but was not found in the application context");
                }
                FastIssuerAuthenticationManager fastIssuerAuthenticationManager = new FastIssuerAuthenticationManager(issuer, jwtHeaderToIssuerMapper, jwtHeaderToIssuerMapperDecider);
                configurer.authenticationManagerResolver(request -> fastIssuerAuthenticationManager);
            } else {
                JwtIssuerAuthenticationManagerResolver jwtIssuerAuthenticationManagerResolver = new JwtIssuerAuthenticationManagerResolver(issuer);

                configurer.authenticationManagerResolver(jwtIssuerAuthenticationManagerResolver);
            }
        }
    }

    private DelegatingOAuth2TokenValidator<Jwt> getJwtValidators(String issuer) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtIssuerValidator(issuer));
        validators.addAll(jwtValidators);
        DelegatingOAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(validators);
        return validator;
    }
}
