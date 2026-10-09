package org.entur.jwt.spring.demo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.atomic.AtomicLong;

/**
 * REST endpoints, secured by the jwt-spring-web module.
 */
@RestController
public class GreetingController {

    private final AtomicLong counter = new AtomicLong();

    @GetMapping("/unprotected")
    public Greeting unprotected() {
        return new Greeting(counter.incrementAndGet(), "Hello unprotected");
    }

    @GetMapping("/protected")
    @PreAuthorize("isFullyAuthenticated()")
    public Greeting protectedGreeting() {
        return new Greeting(counter.incrementAndGet(), "Hello protected");
    }
}
