package org.entur.jwt.spring.filter.log;

import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Map;

public interface JwtMappedDiagnosticContextMapper {

    Map<String, String> getContext(Jwt token);
	
    void addContext(Jwt token);

    void removeContext(Jwt token);
}