package org.entur.jwt.spring.config;

import org.entur.jwt.spring.EnrichedJwtGrantedAuthoritiesConverter;
import org.entur.jwt.spring.JwtAuthorityEnricher;
import org.entur.jwt.spring.decode.ClosableJwtDecoders;
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
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class EnturOauth2ResourceServerCustomizer implements Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> {

    private static final Logger LOGGER = LoggerFactory.getLogger(EnturOauth2ResourceServerCustomizer.class);

    private final List<JwtAuthorityEnricher> jwtAuthorityEnrichers;
    private final JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper;
    private final JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider;
    private final ClosableJwtDecoders decoders;

    public EnturOauth2ResourceServerCustomizer(
            List<JwtAuthorityEnricher> jwtAuthorityEnrichers,
            JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper,
            JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider,
            ClosableJwtDecoders decoders
            ) {
        this.jwtAuthorityEnrichers = jwtAuthorityEnrichers;
        this.jwtHeaderToIssuerMapper = jwtHeaderToIssuerMapper;
        this.jwtHeaderToIssuerMapperDecider = jwtHeaderToIssuerMapperDecider;
        this.decoders = decoders;
    }

    @Override
    public void customize(OAuth2ResourceServerConfigurer<HttpSecurity> configurer) {

        if(LOGGER.isDebugEnabled()) LOGGER.debug("Customize {} issuers", decoders.getJwtDecoders().size());

        Map<String, JwtDecoder> decodersMap = this.decoders.getJwtDecoders();

        Map<String, AuthenticationManager> map = new HashMap<>(); // thread safe for reading
        for (Map.Entry<String, JwtDecoder> entry : decodersMap.entrySet()) {

            JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
            jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new EnrichedJwtGrantedAuthoritiesConverter(jwtAuthorityEnrichers));

            JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(entry.getValue());
            authenticationProvider.setJwtAuthenticationConverter(jwtAuthenticationConverter);

            map.put(entry.getKey(), authenticationProvider::authenticate);
        }

        if(map.size() == 1) {
            AuthenticationManager next = map.values().iterator().next();
            configurer.authenticationManagerResolver(request -> next);
        } else {
            AuthenticationManagerResolver<String> issuer = new IssuerAuthenticationManagerResolver(map);

            if(jwtHeaderToIssuerMapper != null && jwtHeaderToIssuerMapperDecider != null) {
                FastIssuerAuthenticationManager fastIssuerAuthenticationManager = new FastIssuerAuthenticationManager(issuer, jwtHeaderToIssuerMapper, jwtHeaderToIssuerMapperDecider);
                configurer.authenticationManagerResolver(request -> fastIssuerAuthenticationManager);
            } else {
                JwtIssuerAuthenticationManagerResolver jwtIssuerAuthenticationManagerResolver = new JwtIssuerAuthenticationManagerResolver(issuer);

                configurer.authenticationManagerResolver(jwtIssuerAuthenticationManagerResolver);
            }
        }
    }

}
