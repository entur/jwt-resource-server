package org.entur.jwt.spring.rest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicLong;

@RestController
public class GreetingController {

    private static Logger log = LoggerFactory.getLogger(GreetingController.class);

    private final AtomicLong counter = new AtomicLong();

    @GetMapping("/unprotected")
    public Mono<Greeting> unprotected() {
        log.info("Get unprotected method");

        return Mono.just(new Greeting(counter.incrementAndGet(), "Hello unprotected"));
    }

    @PostMapping(path = "/unprotected", consumes = "application/json", produces = "application/json")
    public Mono<Greeting> unprotectedPost(@RequestBody Greeting greeting) {
        log.info("Get unprotected method with POST");

        return Mono.just(new Greeting(counter.incrementAndGet(), "Hello unprotected"));
    }

    @GetMapping("/unprotected/path/{pathVariable}")
    public Mono<Greeting> unprotectedWithPathVariable(@PathVariable("pathVariable") String value) {
        log.info("Get unprotected method with path variable " + value);

        return Mono.just(new Greeting(counter.incrementAndGet(), "Hello unprotected with path variable " + value));
    }

    @GetMapping("/protected")
    @PreAuthorize("isFullyAuthenticated()")
    public Mono<Greeting> body() {
        log.info("Get protected method");

        return ReactiveSecurityContextHolder.getContext()
            .map(securityContext -> (JwtAuthenticationToken) securityContext.getAuthentication())
            .map(authentication -> {
                log.info("Authorization header for {}: {}", authentication.getPrincipal(), authentication.getCredentials());

                return new Greeting(counter.incrementAndGet(), "Hello protected", null, authentication.getAuthorities());
            });

    }

    @PreAuthorize("isFullyAuthenticated() && hasAnyAuthority('configure')")
    @GetMapping("/protected/permission")
    public Mono<Greeting> protectedWithPermission() {
        log.info("Get method protected by partner tenant");

        return ReactiveSecurityContextHolder.getContext()
                .map(securityContext -> (JwtAuthenticationToken) securityContext.getAuthentication())
                .map(authentication -> {
                    log.info("Authorization header for {}: {}", authentication.getPrincipal(), authentication.getCredentials());

                    return new Greeting(counter.incrementAndGet(), "Hello protected with authority", null, authentication.getAuthorities());
                });
    }

}
