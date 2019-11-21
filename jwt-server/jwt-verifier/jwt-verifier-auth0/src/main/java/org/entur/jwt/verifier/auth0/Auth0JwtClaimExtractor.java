package org.entur.jwt.verifier.auth0;

import org.entur.jwt.verifier.JwtClaimException;
import org.entur.jwt.verifier.JwtClaimExtractor;

import com.auth0.jwt.impl.NullClaim;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

public class Auth0JwtClaimExtractor implements JwtClaimExtractor<DecodedJWT> {

	private final String namespace;
	
	public Auth0JwtClaimExtractor(String namespace) {
		super();
		this.namespace = namespace;
	}

	@Override
	public <V> V getClaim(DecodedJWT token, String name, Class<V> type) throws JwtClaimException {
		Claim claim = token.getClaim(name);
		if(namespace != null && claim instanceof NullClaim) {
			claim = token.getClaim(namespace + name);
		}
		if(claim instanceof NullClaim) {
			return null;
		}
		
		return claim.as(type);
	}

}
