package org.entur.jwt.spring.filter;

import org.entur.jwt.verifier.JwtException;

/**
 * 
 * Custom mapping of authorization details.
 * 
 */

public interface JwtDetailsMapper<T> {

	/**
	 * Get details for token, in a context (servlet request, camel exchange etc)
	 * 
	 * @param context current context
	 * @param token verified token
	 * @return authentication details
	 * @throws JwtException
	 */
	
    Object getDetails(Object context, T token) throws JwtException;

}
