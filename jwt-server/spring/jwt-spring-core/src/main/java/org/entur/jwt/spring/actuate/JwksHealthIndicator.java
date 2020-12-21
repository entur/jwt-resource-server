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
        
        logInitialOrChangedState(health);
        if (health.isSuccess()) {
            builder.up();
        } else {
            builder.down();
        }
        builder.withDetail("timestamp", health.getTimestamp());
    }

    protected void logInitialOrChangedState(JwksHealth health) {
        JwksHealth previousHealth = this.previousHealth; // defensive copy
        if(previousHealth != null) {
        	if(!previousHealth.isSuccess() && health.isSuccess()) {
                logger.info("JWKs health transitioned to UP");
        	} else if(previousHealth.isSuccess() && !health.isSuccess()) {
        		logger.warn("JWKs health transitioned to DOWN");
        	}
        } else {
            if(!health.isSuccess()) {
                logger.warn("JWKs health initialized to DOWN");
            } else {
                logger.info("JWKs health initialized to UP");
            }
        }
        this.previousHealth = health;
    }

}