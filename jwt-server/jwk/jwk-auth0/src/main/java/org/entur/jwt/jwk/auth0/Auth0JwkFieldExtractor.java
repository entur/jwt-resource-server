package org.entur.jwt.jwk.auth0;

import org.entur.jwt.jwk.JwkFieldExtractor;

import com.auth0.jwk.Jwk;

public class Auth0JwkFieldExtractor implements JwkFieldExtractor<Jwk> {

	@Override
	public String getJwkId(Jwk jwk) {
		return jwk.getId();
	}
}
