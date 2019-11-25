package org.entur.jwt.spring.filter.resolver;

import java.io.Serializable;
import java.util.Map;

/**
 * Simple wrapper for the JWT payload (main body).
 * 
 */

public class JwtPayload implements Serializable {

	private static final long serialVersionUID = 1L;

	private final Map<String, Object> claims;

	/**
	 * Constructor. Note that all claims, and the map it self is assumed to be serializable.
	 * 
	 * @param claims map with claims
	 */
	
	public JwtPayload(Map<String, Object> claims) {
		super();
		this.claims = claims;
	}
	
	public Map<String, Object> getClaims() {
		return claims;
	}
	
	
}
