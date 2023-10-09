package org.entur.jwt.spring;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.List;

public class Auth0JwtAuthorityEnricher implements JwtAuthorityEnricher {


	@Override
	public void enrich(Collection<GrantedAuthority> current, Jwt jwt) {

		List<String> permissions = jwt.getClaimAsStringList("permissions");
		if (permissions != null && !permissions.isEmpty()) {
			for (String permission : permissions) {
				current.add(new SimpleGrantedAuthority(permission));
			}
		}
	}

}
