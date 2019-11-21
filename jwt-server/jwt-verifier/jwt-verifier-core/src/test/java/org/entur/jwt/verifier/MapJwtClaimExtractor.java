package org.entur.jwt.verifier;

import java.util.Map;

public class MapJwtClaimExtractor implements JwtClaimExtractor<Map<String, Object>>{

	private static final long serialVersionUID = 1L;

	@SuppressWarnings("unchecked")
	@Override
	public <V> V getClaim(Map<String, Object> token, String name, Class<V> type) throws JwtClaimException {
		Object object = token.get(name);
		if(object != null) {
			return (V)object;
		}
		return null;
	}

}
