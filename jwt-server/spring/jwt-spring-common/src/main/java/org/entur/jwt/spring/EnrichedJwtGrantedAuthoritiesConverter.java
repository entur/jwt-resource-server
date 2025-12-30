package org.entur.jwt.spring;


import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class EnrichedJwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final List<JwtAuthorityEnricher> enrichers;

    public EnrichedJwtGrantedAuthoritiesConverter(List<JwtAuthorityEnricher> enrichers) {
        this.enrichers = enrichers;
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        for (JwtAuthorityEnricher enricher : enrichers) {
            enricher.enrich(grantedAuthorities, source);
        }
        return grantedAuthorities;
    }
}
