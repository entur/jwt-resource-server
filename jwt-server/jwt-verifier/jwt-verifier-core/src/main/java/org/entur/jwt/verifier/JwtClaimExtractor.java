package org.entur.jwt.verifier;

import java.io.Serializable;
import java.util.Map;

public interface JwtClaimExtractor<T> extends Serializable { // Serializable as will be stored in Authentication

	<V> V getClaim(T token, String name, Class<V> type) throws JwtClaimException;

	Map<String, Object> getClaims(T token) throws JwtClaimException;
	
}
