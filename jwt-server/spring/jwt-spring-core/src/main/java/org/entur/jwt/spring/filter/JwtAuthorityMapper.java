package org.entur.jwt.spring.filter;

import java.util.List;

import org.entur.jwt.verifier.JwtException;
import org.springframework.security.core.GrantedAuthority;

public interface JwtAuthorityMapper<T> {

	List<GrantedAuthority> getGrantedAuthorities(T token) throws JwtException;
	
}
