package org.entur.jwt.spring.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import reactor.core.publisher.Mono;

import java.util.Map;

public class ReactiveIssuerAuthenticationManagerResolver implements ReactiveAuthenticationManagerResolver<String> {

    private static Logger LOGGER = LoggerFactory.getLogger(ReactiveIssuerAuthenticationManagerResolver.class);

    private final Map<String, ReactiveAuthenticationManager> map;

    public ReactiveIssuerAuthenticationManagerResolver(Map<String, ReactiveAuthenticationManager> map) {
        this.map = map;
    }

    @Override
    public Mono<ReactiveAuthenticationManager> resolve(String issuer) {
        ReactiveAuthenticationManager reactiveAuthenticationManager = map.get(issuer);
        
        return Mono.justOrEmpty(reactiveAuthenticationManager);
    }
}
