package org.entur.jwt.verifier;

import org.entur.jwt.jwk.JwksException;
import org.entur.jwt.jwk.JwksHealthProvider;

public interface JwtVerifier<T> extends JwksHealthProvider {

	/**
	 * Verify token. Non-valid tokens are assumed to be logged and returned as null.
	 * Exceptions are only used if there is an unexpected problem.
	 * 
	 * @param token textual token value - on the form a.b.c
	 * @return a verified token, or null.
	 * @throws JwtException on problem with token (i.e. known signature type not available)
	 * @throws JwksException on problem with signing keys (i.e. authorization server is down) 
	 */

	T verify(String token) throws JwtException, JwksException;

}
