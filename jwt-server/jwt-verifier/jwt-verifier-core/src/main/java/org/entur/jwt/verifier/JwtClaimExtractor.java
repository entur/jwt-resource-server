package org.entur.jwt.verifier;

import java.io.Serializable;

public interface JwtClaimExtractor<T> extends Serializable { // Serializable as will be stored in Authentication

	<V> V getClaim(T token, String name, Class<V> type) throws JwtClaimException;
	
}
