package org.entur.jwt.spring.filter;

import java.util.Map;

import org.entur.jwt.verifier.JwtException;

public class DefaultJwtPrincipalMapper implements JwtPrincipalMapper {

    private static final String CLAIM_SUBJECT = "sub";
    
	@Override
	public Object getPrincipal(Map<String, Object> claims) throws JwtException {
		return claims.get(CLAIM_SUBJECT);
	}

}
