package org.entur.jwt.verifier;

import java.util.HashMap;
import java.util.Map;

import org.entur.jwt.jwk.JwksException;

public class MapJwtVerifier implements JwtVerifier<Map<String, Object>>{

	private Map<String, Map<String, Object>> tokens = new HashMap<>();
	
	@Override
	public Map<String, Object> verify(String token) throws JwtException, JwksException {
		return tokens.get(token);
	}

	public Map<String, Object> put(String key, Map<String, Object> value) {
		return tokens.put(key, value);
	}

	public void clear() {
		tokens.clear();
	}
}
