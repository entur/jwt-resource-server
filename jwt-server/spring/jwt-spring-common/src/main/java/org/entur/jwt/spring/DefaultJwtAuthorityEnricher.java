package org.entur.jwt.spring;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.Collection;

/**
 *
 * Default implementation. Converts the scope claim into SCOPE_xxx permissions via {@linkplain JwtGrantedAuthoritiesConverter}.
 *
 */

public class DefaultJwtAuthorityEnricher implements JwtAuthorityEnricher {

	private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
	@Override
	public void enrich(Collection<GrantedAuthority> current, Jwt jwt) {
		Collection<GrantedAuthority> convert = jwtGrantedAuthoritiesConverter.convert(jwt);

		current.addAll(convert);
	}

	public JwtGrantedAuthoritiesConverter getJwtGrantedAuthoritiesConverter() {
		return jwtGrantedAuthoritiesConverter;
	}
}
