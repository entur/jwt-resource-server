package org.entur.jwt.spring.actuate;

import org.entur.jwt.jwk.JwksHealth;
import org.entur.jwt.verifier.JwtVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.health.AbstractHealthIndicator;
import org.springframework.boot.actuate.health.Health;

/**
 * 
 * Health indicator.
 * 
 */

public class JwksHealthIndicator extends AbstractHealthIndicator {

    protected static final Logger logger = LoggerFactory.getLogger(JwksHealthIndicator.class);

    private final JwtVerifier<?> jwtVerifier;
    
    private JwksHealth previousHealth;

    public JwksHealthIndicator(JwtVerifier<?> jwtVerifier) {
        this.jwtVerifier = jwtVerifier;
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) throws Exception {
        JwksHealth health = jwtVerifier.getHealth(true);
        
        JwksHealth previousHealth = this.previousHealth; // defensive copy
        if(previousHealth != null) {
        	if(!previousHealth.isSuccess() && health.isSuccess()) {
                logger.info("Jwks health transitioned to UP");
        	} else if(previousHealth.isSuccess() && !health.isSuccess()) {
        		logger.warn("Jwks health transitioned to DOWN");
        	}
        } else if(!health.isSuccess()) {
    		logger.warn("Jwks health initialized to DOWN");
        }
        previousHealth = health;
        if (health.isSuccess()) {
            builder.up();
        } else {
            builder.down();
        }
        builder.withDetail("timestamp", health.getTimestamp());
    }

}