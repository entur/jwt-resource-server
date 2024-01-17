package org.entur.jwt.spring.rest;

import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {

    private static Logger log = LoggerFactory.getLogger(GreetingController.class);

    private final AtomicLong counter = new AtomicLong();

    @GetMapping("/unprotected")
    public Greeting unprotected() {
        log.info("Get unprotected method " + SecurityContextHolder.getContext().getAuthentication());

        return new Greeting(counter.incrementAndGet(), "Hello unprotected");
    }

    @PostMapping(path = "/unprotected", consumes = "application/json", produces = "application/json")
    public Greeting unprotectedPost(@RequestBody Greeting greeting) {
        log.info("Get unprotected method with POST " + SecurityContextHolder.getContext().getAuthentication());

        return new Greeting(counter.incrementAndGet(), "Hello unprotected");
    }

    @GetMapping("/unprotected/path/{pathVariable}")
    public Greeting unprotectedWithPathVariable(@PathVariable("pathVariable") String value) {
        log.info("Get unprotected method with path variable " + value);

        return new Greeting(counter.incrementAndGet(), "Hello unprotected with path variable " + value);
    }

    @GetMapping("/protected")
    @PreAuthorize("isFullyAuthenticated()")
    public Greeting body() {
        log.info("Get protected method");

        JwtAuthenticationToken authentication = (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        log.info("Authorization header for {}: {}", authentication.getPrincipal(), authentication.getCredentials());

        return new Greeting(counter.incrementAndGet(), "Hello protected", null, authentication.getAuthorities());
    }

    @PreAuthorize("isFullyAuthenticated() && hasAnyAuthority('SCOPE_configure')")
    @GetMapping("/protected/permission")
    public Greeting protectedWithPermission() {
        log.info("Get method protected by partner tenant");

        JwtAuthenticationToken authentication = (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        log.info("Authorization header for {}: {}", authentication.getPrincipal(), authentication.getCredentials());

        return new Greeting(counter.incrementAndGet(), "Hello protected with authority", null, authentication.getAuthorities());
    }
}
