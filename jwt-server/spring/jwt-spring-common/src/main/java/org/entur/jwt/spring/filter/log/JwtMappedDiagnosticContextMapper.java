package org.entur.jwt.spring.filter.log;

import java.util.Map;

import org.entur.jwt.verifier.JwtClaimException;

public interface JwtMappedDiagnosticContextMapper<T> {

    Map<String, String> getContext(T token) throws JwtClaimException;
	
    void addContext(T token) throws JwtClaimException;

    void removeContext(T token);
}