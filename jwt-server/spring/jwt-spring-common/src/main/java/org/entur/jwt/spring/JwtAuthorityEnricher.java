package org.entur.jwt.spring;

import java.util.Collection;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.core.GrantedAuthority;

public interface JwtAuthorityEnricher {

	void enrich(Collection<GrantedAuthority> current, Jwt jwt);
	
}
