package org.entur.jwt.spring.filter;

import java.io.Serializable;
import java.util.Map;

import org.entur.jwt.verifier.JwtException;

/**
 * 
 * Custom mapping of authorization details.
 * 
 */

public interface JwtDetailsMapper {

	/**
	 * Get details for token, in a context (servlet request, camel exchange etc)
	 * 
	 * @param context current context
	 * @param claims from verified token
	 * @return authentication details
	 * @throws JwtException if an unexpected error
	 */
	
	Serializable getDetails(Object context, Map<String, Object> claims) throws JwtException;

}
