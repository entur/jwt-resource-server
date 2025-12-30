package org.entur.jwt.spring.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import org.entur.jwt.spring.EnrichedJwtGrantedAuthoritiesConverter;
import org.entur.jwt.spring.JwtAuthorityEnricher;
import org.entur.jwt.spring.ReactiveJwtMonoConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class EnturOauth2ResourceServerCustomizer implements Customizer<ServerHttpSecurity.OAuth2ResourceServerSpec> {

    private static Logger LOGGER = LoggerFactory.getLogger(EnturOauth2ResourceServerCustomizer.class);

    private final Map<String, JWKSource> jwkSources;
    private final List<JwtAuthorityEnricher> jwtAuthorityEnrichers;
    private final List<OAuth2TokenValidator<Jwt>> jwtValidators;

    public EnturOauth2ResourceServerCustomizer(Map<String, JWKSource> jwkSources, List<JwtAuthorityEnricher> jwtAuthorityEnrichers, List<OAuth2TokenValidator<Jwt>> jwtValidators) {
        this.jwkSources = jwkSources;
        this.jwtAuthorityEnrichers = jwtAuthorityEnrichers;
        this.jwtValidators = jwtValidators;
    }

    @Override
    public void customize(ServerHttpSecurity.OAuth2ResourceServerSpec configurer) {

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

            decoder.setJwtValidator(getJwtValidators(entry));

            JwtReactiveAuthenticationManager jwtReactiveAuthenticationManager = new JwtReactiveAuthenticationManager(decoder);

            JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
            jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new EnrichedJwtGrantedAuthoritiesConverter(jwtAuthorityEnrichers));

            jwtReactiveAuthenticationManager.setJwtAuthenticationConverter(new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter));

            map.put(entry.getKey(), jwtReactiveAuthenticationManager);
        }

        IssuerAuthenticationManagerResolver issuer = new IssuerAuthenticationManagerResolver(map);

        JwtIssuerReactiveAuthenticationManagerResolver jwtIssuerAuthenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(issuer);

        configurer.authenticationManagerResolver(jwtIssuerAuthenticationManagerResolver);
    }

    private static <C extends SecurityContext> JWTClaimsSet createClaimsSet(JWTProcessor<C> jwtProcessor,
                                                                            JWT parsedToken, C context) {
        try {
            return jwtProcessor.process(parsedToken, context);
        } catch (BadJOSEException ex) {
            throw new BadJwtException("Failed to validate the token", ex);
        } catch (JOSEException ex) {
            throw new JwtException("Failed to validate the token", ex);
        }
    }


    private DelegatingOAuth2TokenValidator<Jwt> getJwtValidators(Map.Entry<String, JWKSource> entry) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtIssuerValidator(entry.getKey())); // this check is implicit, but lets add it regardless
        validators.addAll(jwtValidators);
        DelegatingOAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(validators);
        return validator;
    }
}
