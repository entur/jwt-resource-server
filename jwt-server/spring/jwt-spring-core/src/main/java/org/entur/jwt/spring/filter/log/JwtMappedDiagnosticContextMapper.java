package org.entur.jwt.spring.filter.log;

import org.entur.jwt.verifier.JwtClaimException;

public interface JwtMappedDiagnosticContextMapper<T> {

	void addContext(T token) throws JwtClaimException;

	void removeContext(T token);
}