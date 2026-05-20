package org.entur.jwt.spring.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class IssuerAuthenticationManagerResolver implements AuthenticationManagerResolver<String> {

    private static Logger LOGGER = LoggerFactory.getLogger(IssuerAuthenticationManagerResolver.class);

    private final ConcurrentHashMap<String, AuthenticationManager> map;

    public IssuerAuthenticationManagerResolver(Map<String, AuthenticationManager> map) {
        this.map = new ConcurrentHashMap<>(map);
    }

    /** Replaces or adds the {@link AuthenticationManager} for the given issuer. */
    public void updateManager(String issuer, AuthenticationManager manager) {
        map.put(issuer, manager);
    }

    @Override
    public AuthenticationManager resolve(String issuer) {
        return map.get(issuer);
    }
}
