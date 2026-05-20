package org.entur.jwt.spring.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class IssuerAuthenticationManagerResolver implements ReactiveAuthenticationManagerResolver<String> {

    private static Logger LOGGER = LoggerFactory.getLogger(IssuerAuthenticationManagerResolver.class);

    private final ConcurrentHashMap<String, ReactiveAuthenticationManager> map;

    public IssuerAuthenticationManagerResolver(Map<String, ReactiveAuthenticationManager> map) {
        this.map = new ConcurrentHashMap<>(map);
    }

    /** Replaces or adds the {@link ReactiveAuthenticationManager} for the given issuer. */
    public void updateManager(String issuer, ReactiveAuthenticationManager manager) {
        map.put(issuer, manager);
    }

    @Override
    public Mono<ReactiveAuthenticationManager> resolve(String issuer) {
        ReactiveAuthenticationManager reactiveAuthenticationManager = map.get(issuer);

        return Mono.justOrEmpty(reactiveAuthenticationManager);
    }
}
