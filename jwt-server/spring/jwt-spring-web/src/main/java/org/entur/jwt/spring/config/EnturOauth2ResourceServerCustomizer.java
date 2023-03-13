package org.entur.jwt.spring.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSAlgorithmFamilyJWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.entur.jwt.spring.EnrichedJwtGrantedAuthoritiesConverter;
import org.entur.jwt.spring.JwtAuthorityEnricher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class EnturOauth2ResourceServerCustomizer implements Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> {

    private static Logger LOGGER = LoggerFactory.getLogger(EnturOauth2ResourceServerCustomizer.class);

    private final Map<String, JWKSource> jwkSources;
    private final List<JwtAuthorityEnricher> jwtAuthorityEnrichers;

    public EnturOauth2ResourceServerCustomizer(Map<String, JWKSource> jwkSources, List<JwtAuthorityEnricher> jwtAuthorityEnrichers) {
        this.jwkSources = jwkSources;
        this.jwtAuthorityEnrichers = jwtAuthorityEnrichers;
    }

    @Override
    public void customize(OAuth2ResourceServerConfigurer<HttpSecurity> configurer) {

        LOGGER.info("Customize " + jwkSources.size() + " issuers");

        Map<String, AuthenticationManager> map = new HashMap<>(); // thread safe for reading

        for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {
            JWKSource jwkSource = entry.getValue();

            DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(new JWSAlgorithmFamilyJWSKeySelector<>(JWSAlgorithm.Family.SIGNATURE, jwkSource));

            JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(new NimbusJwtDecoder(jwtProcessor));

            JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
            jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new EnrichedJwtGrantedAuthoritiesConverter(jwtAuthorityEnrichers));
            
			authenticationProvider.setJwtAuthenticationConverter(jwtAuthenticationConverter);
            
            map.put(entry.getKey(), authenticationProvider::authenticate);
        }

        AuthenticationManagerResolver<String> issuer = new IssuerAuthenticationManagerResolver(map);

        JwtIssuerAuthenticationManagerResolver jwtIssuerAuthenticationManagerResolver = new JwtIssuerAuthenticationManagerResolver(issuer);

        configurer.authenticationManagerResolver(jwtIssuerAuthenticationManagerResolver);
    }
}
