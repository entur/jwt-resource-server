package org.entur.jwt.spring.filter.log;

import java.util.Map;

import org.springframework.security.oauth2.jwt.Jwt;

public interface JwtMappedDiagnosticContextMapper {

    Map<String, String> getContext(Jwt token);
	
    void addContext(Jwt token);

    void removeContext(Jwt token);
}