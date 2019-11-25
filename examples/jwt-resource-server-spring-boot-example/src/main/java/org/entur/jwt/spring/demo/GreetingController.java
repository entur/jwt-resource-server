package org.entur.jwt.spring.demo;


import java.util.concurrent.atomic.AtomicLong;

import org.entur.jwt.spring.filter.JwtAuthenticationToken;
import org.entur.jwt.spring.filter.resolver.JwtPayload;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
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
    
    @GetMapping("/protected")
    @PreAuthorize("isFullyAuthenticated()")
    public Greeting body() {
        log.info("Get protected method");
        
        JwtAuthenticationToken authentication = (JwtAuthenticationToken)SecurityContextHolder.getContext().getAuthentication();
        
    	log.info("Authorization header: {}", authentication.getCredentials());
    	
        return new Greeting(counter.incrementAndGet(), "Hello protected.");
    }

    @GetMapping("/protected/withArgument")
    @PreAuthorize("isFullyAuthenticated()")
    public Greeting protectedWithPartnerTenant(JwtPayload body) {
        log.info("Get method protected with argument resolver");

    	log.info("Claims: {}", body.getClaims());
    	
        return new Greeting(counter.incrementAndGet(), "Hello protected tenant.");
    }

    @PreAuthorize("isFullyAuthenticated() && hasAnyAuthority('configure')")
    @GetMapping("/protected/withPermission") 
    public Greeting protectedWithPermission(JwtPayload body) {
        log.info("Get method protected by permission");
        
    	log.info("Claims: {}", body.getClaims());
        
        return new Greeting(counter.incrementAndGet(), "Hello protected tenant.");
    }
    
    

}