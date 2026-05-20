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
import org.entur.jwt.spring.actuate.ListEventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class EnturOauth2ResourceServerCustomizer implements Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> {

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
    public void customize(OAuth2ResourceServerConfigurer<HttpSecurity> configurer) {

        Map<String, JWKSource> jwkSources = jwkSourceMap.getJwkSources();

        if(LOGGER.isDebugEnabled()) LOGGER.debug("Customize {} issuers", jwkSources.size());

        Map<String, AuthenticationManager> map = new HashMap<>(); // thread safe for reading

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

            map.put(entry.getKey(), authenticationProvider::authenticate);
        }

        if(map.size() == 1) {
            AuthenticationManager next = map.values().iterator().next();
            configurer.authenticationManagerResolver(request -> next);
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
            configurer.authenticationManagerResolver(new JwtKidCachingAuthenticationManagerResolver(issuerResolver, kidIssuerCacheFactory.getCache()));
        }
    }

    private AuthenticationManager buildManagerFromJwkSet(String issuer, JWKSet jwkSet) {
        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.Family.SIGNATURE, new ImmutableJWKSet<>(jwkSet));
        jwtProcessor.setJWSKeySelector(keySelector);

        NimbusJwtDecoder nimbusJwtDecoder = new NimbusJwtDecoder(jwtProcessor);
        nimbusJwtDecoder.setJwtValidator(getJwtValidators(issuer));

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new EnrichedJwtGrantedAuthoritiesConverter(jwtAuthorityEnrichers));

        JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(nimbusJwtDecoder);
        authenticationProvider.setJwtAuthenticationConverter(jwtAuthenticationConverter);

        return authenticationProvider::authenticate;
    }

    private DelegatingOAuth2TokenValidator<Jwt> getJwtValidators(String issuer) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtIssuerValidator(issuer));
        validators.addAll(jwtValidators);
        DelegatingOAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(validators);
        return validator;
    }
}
