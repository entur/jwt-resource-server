package org.entur.jwt.spring.camel;

import java.util.Set;

import javax.security.auth.Subject;

import org.apache.camel.Exchange;
import org.entur.jwt.spring.filter.JwtAuthenticationToken;
import org.entur.jwt.verifier.JwtClaimException;

public class ExchangeJwtClaimExtractor {

	public static <V> V extract(Exchange e, String name, Class<V> type) throws JwtClaimException {
	    Subject subject = e.getIn().getHeader(Exchange.AUTHENTICATION, Subject.class);
	    Set<JwtAuthenticationToken> principals = subject.getPrincipals(JwtAuthenticationToken.class);
	    if(principals.isEmpty()) {
	    	throw new JwtClaimException("JWT authentication not found in exchange");
	    }
	    JwtAuthenticationToken next = principals.iterator().next();
	    V claim = next.getClaim(name, type);
	    if(claim == null) {
	    	throw new JwtClaimException("JWT claim " + name + " not found in token");
	    }
	    return claim;
	}

}
