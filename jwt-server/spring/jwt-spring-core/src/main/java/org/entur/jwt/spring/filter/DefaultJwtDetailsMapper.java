package org.entur.jwt.spring.filter;

import org.entur.jwt.verifier.JwtException;

public class DefaultJwtDetailsMapper<T> implements JwtDetailsMapper<T> {

	@Override
	public Object getDetails(Object request, T token) throws JwtException {
		return null;
	}

}
