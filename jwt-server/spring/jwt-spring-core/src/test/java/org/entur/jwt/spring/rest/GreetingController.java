package org.entur.jwt.spring.rest;

import java.util.concurrent.atomic.AtomicLong;

import org.entur.jwt.spring.filter.JwtAuthenticationToken;
import org.entur.jwt.spring.rest.config.PartnerTenant;
import org.entur.jwt.spring.rest.config.Tenant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
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
        log.info("Get unprotected method");

        return new Greeting(counter.incrementAndGet(), "Hello unprotected");
    }

    @PostMapping(path = "/unprotected", consumes = "application/json", produces = "application/json")
    public Greeting unprotectedPost(@RequestBody Greeting greeting) {
        log.info("Get unprotected method with POST");

        return new Greeting(counter.incrementAndGet(), "Hello unprotected");
    }

    @GetMapping("/unprotected/path/{pathVariable}")
    public Greeting unprotectedWithPathVariable(@PathVariable("pathVariable") String value) {
        log.info("Get unprotected method with path variable " + value);

        return new Greeting(counter.incrementAndGet(), "Hello unprotected with path variable " + value);
    }

    @GetMapping("/unprotected/optionalTenant")
    public Greeting unprotectedWithOptionalTenant(@Nullable Tenant tenant) {
        if (tenant != null) {

            log.info("Get unprotected method with optional tenant present " + tenant);
            return new Greeting(counter.incrementAndGet(), "Hello unprotected with optional tenant " + tenant);
        } else {
            log.info("Get unprotected method with optional tenant not present");
            return new Greeting(counter.incrementAndGet(), "Hello unprotected without optional tenant");
        }
    }

    @GetMapping("/unprotected/requiredTenant")
    public Greeting unprotectedWithRequiredTenant(Tenant tenant) {
        throw new RuntimeException("DO NOT IMPLEMENT IMPLICIT ACCESS CONTROL THIS WAY");
    }

    @GetMapping("/protected")
    @PreAuthorize("isFullyAuthenticated()")
    public Greeting body() {
        log.info("Get protected method");

        JwtAuthenticationToken authentication = (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        log.info("Authorization header: {}", authentication.getCredentials());

        return new Greeting(counter.incrementAndGet(), "Hello protected", null, authentication.getAuthorities());
    }
    
    @GetMapping("/protected/optionalTenant")
    public Greeting protectedWithRequiredTenant(@Nullable Tenant tenant) {
        if (tenant != null) {

            log.info("Get protected method with optional tenant present " + tenant);
            return new Greeting(counter.incrementAndGet(), "Hello protected with optional tenant " + tenant);
        } else {
            log.info("Get protected method with optional tenant not present");
            return new Greeting(counter.incrementAndGet(), "Hello protected without optional tenant");
        }
    }
    
    @GetMapping("/protected/requiredTenant")
    @PreAuthorize("isFullyAuthenticated()")
    public Greeting protectedWithPartnerTenant(Tenant tenant) {
        log.info("Get method protected by tenant");

        JwtAuthenticationToken authentication = (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        log.info("Authorization header: {}", authentication.getCredentials());

        return new Greeting(counter.incrementAndGet(), "Hello protected tenant " + tenant.getOrganisationId(), tenant.getClass(), authentication.getAuthorities());
    }

    @PreAuthorize("isFullyAuthenticated()")
    @GetMapping("/protected/requiredPartnerTenant")
    public Greeting protectedWithSpcificPartnerTenant(PartnerTenant partner) {
        log.info("Get method protected by partner tenant");

        JwtAuthenticationToken authentication = (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        log.info("Authorization header: {}", authentication.getCredentials());

        return new Greeting(counter.incrementAndGet(), "Hello protected partner tenant " + partner.getOrganisationId(), partner.getClass(), authentication.getAuthorities());
    }

    @PreAuthorize("isFullyAuthenticated() && hasAnyAuthority('configure')")
    @GetMapping("/protected/permission")
    public Greeting protectedWithPermission(PartnerTenant partner) {
        log.info("Get method protected by partner tenant");

        JwtAuthenticationToken authentication = (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        log.info("Authorization header: {}", authentication.getCredentials());

        return new Greeting(counter.incrementAndGet(), "Hello protected partner tenant " + partner.getOrganisationId() + " with authority", partner.getClass(), authentication.getAuthorities());
    }

}