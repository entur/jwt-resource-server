package org.entur.jwt.spring.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import jakarta.servlet.http.HttpServletRequest;
import org.entur.jwt.spring.EnrichedJwtGrantedAuthoritiesConverter;
import org.entur.jwt.spring.JwtAuthorityEnricher;
import org.entur.jwt.spring.actuate.ListEventListener;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.entur.jwt.spring.properties.JwtDecodeProperties;
import org.entur.jwt.spring.properties.JwtHeaderDecodeProperties;
import org.jspecify.annotations.NonNull;
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
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class EnturOauth2ResourceServerCustomizer implements Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> {

    private static Logger LOGGER = LoggerFactory.getLogger(EnturOauth2ResourceServerCustomizer.class);

    private final Map<String, JWKSource> jwkSources;
    private final List<JwtAuthorityEnricher> jwtAuthorityEnrichers;
    private final List<OAuth2TokenValidator<Jwt>> jwtValidators;
    private final Map<String, ListEventListener> jwkEventListeners;
    private final JwtDecodeProperties properties;

    public EnturOauth2ResourceServerCustomizer(JwtDecodeProperties properties, Map<String, JWKSource> jwkSources, Map<String, ListEventListener> jwkEventListeners, List<JwtAuthorityEnricher> jwtAuthorityEnrichers, List<OAuth2TokenValidator<Jwt>> jwtValidators) {
        this.properties = properties;
        this.jwkSources = jwkSources;
        this.jwkEventListeners = jwkEventListeners;
        this.jwtAuthorityEnrichers = jwtAuthorityEnrichers;
        this.jwtValidators = jwtValidators;
    }

    @Override
    public void customize(OAuth2ResourceServerConfigurer<HttpSecurity> configurer) {

        if(LOGGER.isDebugEnabled()) LOGGER.debug("Customize {} issuers", jwkSources.size());

        if(jwkSources.size() == 1) {
            String issuer = jwkSources.keySet().iterator().next();
            JWKSource jwkSource = jwkSources.get(issuer);

            JwtAuthenticationProvider authenticationProvider = getJwtAuthenticationProvider(issuer, jwkSource);

            AuthenticationManagerResolver<HttpServletRequest> resolver = request -> authenticationProvider::authenticate;
            configurer.authenticationManagerResolver(resolver);
        } else {
            // create multi-tenant decoder which attempts to avoid parsing the
            // JWT to map the JWT to the correct decoder

            Map<String, AuthenticationManager> map = new HashMap<>(); // thread safe for reading

            for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {
                JWKSource jwkSource = entry.getValue();
                String issuer = entry.getKey();

                JwtAuthenticationProvider authenticationProvider = getJwtAuthenticationProvider(issuer, jwkSource);

                AuthenticationManager authenticationManager = authenticationProvider::authenticate;
                map.put(entry.getKey(), authenticationManager);
            }

            AuthenticationManagerResolver<String> issuer = new IssuerAuthenticationManagerResolver(map);

            JwtHeaderDecodeProperties header = properties.getHeader();
            if(header.getMapHeaderToIssuer().isEnabled()) {
                JwtHeaderToIssuerMapper mapper = new JwtHeaderToIssuerMapper();
                FastIssuerAuthenticationManager jwtIssuerAuthenticationManagerResolver = new FastIssuerAuthenticationManager(issuer, mapper);
                configurer.authenticationManagerResolver(request -> jwtIssuerAuthenticationManagerResolver);
            } else {
                JwtIssuerAuthenticationManagerResolver jwtIssuerAuthenticationManagerResolver = new JwtIssuerAuthenticationManagerResolver(issuer);
                configurer.authenticationManagerResolver(jwtIssuerAuthenticationManagerResolver);
            }
        }
    }

    private @NonNull JwtAuthenticationProvider getJwtAuthenticationProvider(String issuer, JWKSource jwkSource) {
        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(JWSAlgorithm.Family.SIGNATURE, jwkSource);
        jwtProcessor.setJWSKeySelector(keySelector);

        NimbusJwtDecoder nimbusJwtDecoder = new NimbusJwtDecoder(jwtProcessor);
        nimbusJwtDecoder.setJwtValidator(getJwtValidators(issuer));

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new EnrichedJwtGrantedAuthoritiesConverter(jwtAuthorityEnrichers));

        JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(nimbusJwtDecoder);
        authenticationProvider.setJwtAuthenticationConverter(jwtAuthenticationConverter);
        return authenticationProvider;
    }

    private DelegatingOAuth2TokenValidator<Jwt> getJwtValidators(String issuer) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtIssuerValidator(issuer));
        validators.addAll(jwtValidators);
        DelegatingOAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(validators);
        return validator;
    }
}
