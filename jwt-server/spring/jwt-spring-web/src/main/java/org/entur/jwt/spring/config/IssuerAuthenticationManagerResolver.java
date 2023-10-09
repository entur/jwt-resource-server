package org.entur.jwt.spring.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;

import java.util.Map;

public class IssuerAuthenticationManagerResolver implements AuthenticationManagerResolver<String> {

    private static Logger LOGGER = LoggerFactory.getLogger(IssuerAuthenticationManagerResolver.class);

    private final Map<String, AuthenticationManager> map;

    public IssuerAuthenticationManagerResolver(Map<String, AuthenticationManager> map) {
        this.map = map;
    }

    @Override
    public AuthenticationManager resolve(String issuer) {
        return map.get(issuer);
    }
}
