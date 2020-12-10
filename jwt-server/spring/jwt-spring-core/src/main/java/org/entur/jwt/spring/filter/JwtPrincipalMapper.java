package org.entur.jwt.spring.filter;

import java.io.Serializable;
import java.util.Map;

import org.entur.jwt.verifier.JwtException;

/**
 * 
 * Custom mapping of authorization details.
 * 
 */

public interface JwtPrincipalMapper {

	/**
	 * Get principal for token, in a context (servlet request, camel exchange etc)
	 * 
	 * @param claims from verified token
	 * @return authentication principal
	 * @throws JwtException if an unexpected error
	 */
	
	Serializable getPrincipal(Map<String, Object> claims) throws JwtException;

}
