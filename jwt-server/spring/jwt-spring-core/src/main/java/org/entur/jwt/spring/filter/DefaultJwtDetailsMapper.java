package org.entur.jwt.spring.filter;

import java.util.Map;

import org.entur.jwt.verifier.JwtException;

public class DefaultJwtDetailsMapper implements JwtDetailsMapper {

	@Override
	public Object getDetails(Object request, Map<String, Object> claims) throws JwtException {
		return null;
	}

}
