package org.entur.jwt.spring.camel;

import javax.servlet.http.HttpServletRequest;

import org.apache.camel.Exchange;
import org.apache.camel.Processor;

/**
 * A {@linkplain Processor} which, if present, extracts the Json Web Token from
 * the message {@linkplain HttpServletRequest} Authorization header and saves it to the message
 * {@linkplain Exchange#AUTHENTICATION}. If not present, an anonymous authentication object is
 * used.
 * <br>
 * This implementation assumes that SpringSecurityAuthorizationPolicy#setUseThreadSecurityContext
 * is used to disable thread local authentication.
 * 
 */

public interface JwtAuthenticationProcessor extends Processor {	

	void process(Exchange exchange);
}
