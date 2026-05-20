package org.entur.jwt.spring.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.entur.jwt.spring.EnrichedJwtGrantedAuthoritiesConverter;
import org.entur.jwt.spring.IssuerJwkContext;
import org.entur.jwt.spring.JwtAuthorityEnricher;
import org.entur.jwt.spring.JwtKidIssuerCacheFactory;
import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.ReactiveJwtMonoConverter;
import org.entur.jwt.spring.actuate.ListEventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class EnturOauth2ResourceServerCustomizer implements Customizer<ServerHttpSecurity.OAuth2ResourceServerSpec> {

    private static Logger LOGGER = LoggerFactory.getLogger(EnturOauth2ResourceServerCustomizer.class);

    private final JwkSourceMap jwkSourceMap;
    private final List<JwtAuthorityEnricher> jwtAuthorityEnrichers;
    private final List<OAuth2TokenValidator<Jwt>> jwtValidators;

    public EnturOauth2ResourceServerCustomizer(JwkSourceMap jwkSourceMap, List<JwtAuthorityEnricher> jwtAuthorityEnrichers, List<OAuth2TokenValidator<Jwt>> jwtValidators) {
        this.jwkSourceMap = jwkSourceMap;
        this.jwtAuthorityEnrichers = jwtAuthorityEnrichers;
        this.jwtValidators = jwtValidators;
    }

    @Override
    public void customize(ServerHttpSecurity.OAuth2ResourceServerSpec configurer) {

        Map<String, JWKSource> jwkSources = jwkSourceMap.getJwkSources();

        if(LOGGER.isInfoEnabled()) LOGGER.info("Customize {} issuers", jwkSources.size());

        Map<String, ReactiveAuthenticationManager> map = new HashMap<>(); // thread safe for reading

        for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {
            JWKSource jwkSource = entry.getValue();

            JWSVerificationKeySelector verificationKeySelector = new JWSVerificationKeySelector(JWSAlgorithm.Family.SIGNATURE, jwkSource);

            DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(verificationKeySelector);
            jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
            });

            ReactiveJwtMonoConverter reactiveConverter = new ReactiveJwtMonoConverter(jwtProcessor, verificationKeySelector);

            NimbusReactiveJwtDecoder decoder = new NimbusReactiveJwtDecoder(reactiveConverter);

            decoder.setJwtValidator(getJwtValidators(entry.getKey()));

            JwtReactiveAuthenticationManager jwtReactiveAuthenticationManager = new JwtReactiveAuthenticationManager(decoder);

            JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
            jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new EnrichedJwtGrantedAuthoritiesConverter(jwtAuthorityEnrichers));

            jwtReactiveAuthenticationManager.setJwtAuthenticationConverter(new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter));

            map.put(entry.getKey(), jwtReactiveAuthenticationManager);
        }

        if(map.size() == 1) {
            ReactiveAuthenticationManager next = map.values().iterator().next();
            Mono<ReactiveAuthenticationManager> authenticationManager = Mono.just(next);
            configurer.authenticationManagerResolver(request -> authenticationManager);
        } else {
            JwtKidIssuerCacheFactory kidIssuerCacheFactory = new JwtKidIssuerCacheFactory(jwkSources.keySet());
            IssuerAuthenticationManagerResolver issuerResolver = new IssuerAuthenticationManagerResolver(map);
            @SuppressWarnings("unchecked")
            Map<String, ListEventListener> eventListeners = jwkSourceMap.getJwkEventListeners();
            for (Map.Entry<String, ListEventListener> entry : eventListeners.entrySet()) {
                String issuer = entry.getKey();
                IssuerJwkContext context = new IssuerJwkContext(
                        issuer,
                        kidIssuerCacheFactory::onJwkSetUpdated,
                        (iss, jwkSet) -> issuerResolver.updateManager(iss, buildManagerFromJwkSet(iss, jwkSet)));
                entry.getValue().addEventListener(context.getEventListener());
            }
            configurer.authenticationManagerResolver(new JwtKidCachingReactiveAuthenticationManagerResolver(issuerResolver, kidIssuerCacheFactory.getCache()));
        }
    }

    private ReactiveAuthenticationManager buildManagerFromJwkSet(String issuer, JWKSet jwkSet) {
        ImmutableJWKSet<SecurityContext> immutableJwkSet = new ImmutableJWKSet<>(jwkSet);
        JWSVerificationKeySelector verificationKeySelector = new JWSVerificationKeySelector(JWSAlgorithm.Family.SIGNATURE, immutableJwkSet);

        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(verificationKeySelector);
        jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {});

        ReactiveJwtMonoConverter reactiveConverter = new ReactiveJwtMonoConverter(jwtProcessor, verificationKeySelector);

        NimbusReactiveJwtDecoder decoder = new NimbusReactiveJwtDecoder(reactiveConverter);
        decoder.setJwtValidator(getJwtValidators(issuer));

        JwtReactiveAuthenticationManager mgr = new JwtReactiveAuthenticationManager(decoder);

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new EnrichedJwtGrantedAuthoritiesConverter(jwtAuthorityEnrichers));
        mgr.setJwtAuthenticationConverter(new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter));

        return mgr;
    }

    private DelegatingOAuth2TokenValidator<Jwt> getJwtValidators(String issuer) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtIssuerValidator(issuer));
        validators.addAll(jwtValidators);
        DelegatingOAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(validators);
        return validator;
    }
}
