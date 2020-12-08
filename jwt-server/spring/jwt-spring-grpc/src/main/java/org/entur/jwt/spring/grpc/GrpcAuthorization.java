package org.entur.jwt.spring.grpc;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.entur.jwt.spring.filter.JwtAuthenticationToken;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.GrantedAuthority;

import io.grpc.Context;

/**
 * Helper class for manual authorization checking.
 *
 */

public interface GrpcAuthorization {

    public static final Context.Key<Object> SECURITY_CONTEXT_AUTHENTICATION = Context.key("SECURITY_CONTEXT_AUTHENTICATION"); 
    public static final Context.Key<Object> SECURITY_CONTEXT_MDC = Context.key("SECURITY_CONTEXT_MDC"); 

    public default Object getPrincial() {
        Object object = GrpcAuthorization.SECURITY_CONTEXT_AUTHENTICATION.get();
        if(object instanceof JwtAuthenticationToken) {
        	JwtAuthenticationToken authentication = (JwtAuthenticationToken)object;
            return authentication.getPrincipal();
        }
        return null;
    }
    
    public default JwtAuthenticationToken getToken() {
        Object object = GrpcAuthorization.SECURITY_CONTEXT_AUTHENTICATION.get();
        if(object instanceof JwtAuthenticationToken) {
            return (JwtAuthenticationToken) object;
        }
        return null;
    }    
    	
    public default void requireAnyAudience(String ... audiences) {
    	Set<String> set = new HashSet<>();
    	Collections.addAll(set, audiences);

    	requireAnyAudience(set);
    }

    public default void requireAnyAudience(Set<String> audiences) {
        Object object = GrpcAuthorization.SECURITY_CONTEXT_AUTHENTICATION.get();
        if(object instanceof JwtAuthenticationToken) {
        	if(!hasAnyAudience((JwtAuthenticationToken)object, audiences)) {
    		    throw new AccessDeniedException("Not amoung required audiences.");
        	}
            // at least one of the required audiences was found
        } else {
        	throw new AuthenticationCredentialsNotFoundException("");
        }
    }

	public default boolean hasAnyAudience(JwtAuthenticationToken authentication, Set<String> audiences) {
		List<String> jwtAudiences = authentication.getClaim("aud", List.class);
		
		return jwtAudiences != null && !Collections.disjoint(audiences, jwtAudiences);
	}
    
    public default void requireAnyAuthority(String ... authorities) {
        Object object = GrpcAuthorization.SECURITY_CONTEXT_AUTHENTICATION.get();
        if(object instanceof JwtAuthenticationToken) {
        	JwtAuthenticationToken authentication = (JwtAuthenticationToken)object;

            if(!hasAnyAuthority(authentication, authorities)) {
            	throw new AccessDeniedException("");
            }
        }
        throw new AuthenticationCredentialsNotFoundException("");
    }

	public default boolean hasAnyAuthority(JwtAuthenticationToken authentication, String... authorities) {
		Collection<GrantedAuthority> grantedAuthorities = authentication.getAuthorities();
		for (GrantedAuthority grantedAuthority : grantedAuthorities) {
		    for (String string : authorities) {
		        if(grantedAuthority.getAuthority().equals(string)) {
		            return true;
		        }
		    }
		}
		return false;
	}

    public default void requireAllAuthorities(String ... authorities) {
    	Set<String> set = new HashSet<>();
    	Collections.addAll(set, authorities);
    	requireAllAuthorities(set);
    }

    public default void requireAllAuthorities(Set<String> authorities) {
        Object object = GrpcAuthorization.SECURITY_CONTEXT_AUTHENTICATION.get();
        if(object instanceof JwtAuthenticationToken) {
        	if(hasAllAuthorities((JwtAuthenticationToken)object, authorities)) {
        		return;
        	}
        	throw new AccessDeniedException("");
        }
        
        throw new AuthenticationCredentialsNotFoundException("");
    }

	public default boolean hasAllAuthorities(JwtAuthenticationToken authentication, Set<String> authorities) {
		Set<String> grantedAuthorities = authentication.getAuthorities().stream().map(a -> a.getAuthority()).collect(Collectors.toSet());
		return grantedAuthorities.containsAll(authorities);
	}    

}
