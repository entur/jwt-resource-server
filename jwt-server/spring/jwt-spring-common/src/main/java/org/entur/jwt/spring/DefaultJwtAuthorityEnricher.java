package org.entur.jwt.spring;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

public class DefaultJwtAuthorityEnricher implements JwtAuthorityEnricher {

	private static final String DEFAULT_AUTHORITY_PREFIX = "SCOPE_";

	@Override
	public void enrich(Collection<GrantedAuthority> current, Jwt jwt) {
		Set<GrantedAuthority> enriched = new HashSet<>(current.size() * 2);
		
		for(GrantedAuthority ga : current) {
			if(ga.getAuthority().startsWith(DEFAULT_AUTHORITY_PREFIX)) {
				enriched.add(new SimpleGrantedAuthority(ga.getAuthority().substring(DEFAULT_AUTHORITY_PREFIX.length())));
			}
		}
		
		current.addAll(enriched);
	}

}
