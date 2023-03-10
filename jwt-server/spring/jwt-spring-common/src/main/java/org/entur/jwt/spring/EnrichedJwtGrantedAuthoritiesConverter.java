package org.entur.jwt.spring;


import java.util.ArrayList;
import java.util.Collection;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

public class EnrichedJwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
	
    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    private final JwtAuthorityEnricher enricher;
    
    public EnrichedJwtGrantedAuthoritiesConverter(JwtAuthorityEnricher enricher) {
		this.enricher = enricher;
		
		jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");
	}
    
    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {
        Collection<GrantedAuthority> grantedAuthorities = jwtGrantedAuthoritiesConverter.convert(source);

        if(grantedAuthorities == null) {
            grantedAuthorities = new ArrayList<>();
        }
        
        enricher.enrich(grantedAuthorities, source);

        return grantedAuthorities;
    }
}
