package org.entur.jwt.spring.demo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.atomic.AtomicLong;

@RestController
public class GreetingController {

    private static Logger log = LoggerFactory.getLogger(GreetingController.class);

    private final AtomicLong counter = new AtomicLong();

    @GetMapping("/unprotected")
    public Greeting unprotected() {
        log.info("Get unprotected method");

        return new Greeting(counter.incrementAndGet(), "Hello unprotected");
    }

    @GetMapping("/protected")
    @PreAuthorize("isFullyAuthenticated()")
    public Greeting body() {
        log.info("Get protected method");

        JwtAuthenticationToken authentication = (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        log.info("Authorization header: {}", authentication.getCredentials());

        return new Greeting(counter.incrementAndGet(), "Hello protected.");
    }

    @PreAuthorize("isFullyAuthenticated() && hasAnyAuthority('configure')")
    @GetMapping("/protected/withPermission")
    public Greeting protectedWithPermission() {
        log.info("Get method protected by permission");

        JwtAuthenticationToken authentication = (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        log.info("Claims: {}", authentication.getCredentials());

        return new Greeting(counter.incrementAndGet(), "Hello protected tenant.");
    }
    
    
    @PreAuthorize("hasPermission('Testing', 'READ')")
    @GetMapping("/protected/permission/read")
    public Greeting protectedWithPermissionRead() {
        log.info("Get method protected by partner tenant and read permission");
        return new Greeting(counter.incrementAndGet(), "Hello protected partner tenant with permission read ");
    }       

}