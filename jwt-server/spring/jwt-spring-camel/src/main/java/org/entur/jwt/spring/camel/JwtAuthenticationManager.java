package org.entur.jwt.spring.camel;

import org.entur.jwt.spring.filter.JwtAuthenticationToken;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;

public class JwtAuthenticationManager implements AuthenticationManager {

	@Override
	public Authentication authenticate(Authentication authentication) {
		if(authentication instanceof JwtAuthenticationToken) {
			return authentication;
		}

		throw new AuthenticationCredentialsNotFoundException("Expected " + JwtAuthenticationToken.class.getName());
	}

}
