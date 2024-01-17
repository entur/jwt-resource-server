package org.entur.jwt.spring;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.Collection;

/**
 *
 * Noop enricher.
 *
 */
public class NoopJwtAuthorityEnricher implements JwtAuthorityEnricher {

	@Override
	public void enrich(Collection<GrantedAuthority> current, Jwt jwt) {
	}

}
