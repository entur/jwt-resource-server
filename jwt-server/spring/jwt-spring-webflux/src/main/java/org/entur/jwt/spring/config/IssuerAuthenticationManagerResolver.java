package org.entur.jwt.spring.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import reactor.core.publisher.Mono;

import java.util.Map;

public class IssuerAuthenticationManagerResolver implements ReactiveAuthenticationManagerResolver<String> {

    private static Logger LOGGER = LoggerFactory.getLogger(IssuerAuthenticationManagerResolver.class);

    private final Map<String, ReactiveAuthenticationManager> map;

    public IssuerAuthenticationManagerResolver(Map<String, ReactiveAuthenticationManager> map) {
        this.map = map;
    }

    @Override
    public Mono<ReactiveAuthenticationManager> resolve(String issuer) {
        ReactiveAuthenticationManager reactiveAuthenticationManager = map.get(issuer);
        
        return Mono.justOrEmpty(reactiveAuthenticationManager);
    }
}
