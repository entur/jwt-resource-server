package org.entur.jwt.spring;


import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class EnrichedJwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    private final List<JwtAuthorityEnricher> enrichers;

    public EnrichedJwtGrantedAuthoritiesConverter(List<JwtAuthorityEnricher> enrichers) {
        this.enrichers = enrichers;

        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {
        Collection<GrantedAuthority> grantedAuthorities = jwtGrantedAuthoritiesConverter.convert(source);

        if (grantedAuthorities == null) {
            grantedAuthorities = new ArrayList<>();
        }

        for (JwtAuthorityEnricher enricher : enrichers) {
            enricher.enrich(grantedAuthorities, source);
        }
        return grantedAuthorities;
    }
}
