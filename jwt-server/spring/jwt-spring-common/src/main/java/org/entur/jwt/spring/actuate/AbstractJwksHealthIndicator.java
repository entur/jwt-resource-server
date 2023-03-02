package org.entur.jwt.spring.actuate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.health.AbstractHealthIndicator;
import org.springframework.boot.actuate.health.Health;

import java.io.Closeable;
import java.io.IOException;

/**
 * 
 * Health indicator.
 * 
 */

public abstract class AbstractJwksHealthIndicator extends AbstractHealthIndicator {

    protected static final Logger logger = LoggerFactory.getLogger(AbstractJwksHealthIndicator.class);

    private JwksHealth previousHealth;


    @Override
    protected void doHealthCheck(Health.Builder builder) throws Exception {

        JwksHealth health = getJwksHealth();
        if(health != null) {
	        logInitialOrChangedState(health);
	        if (health.isSuccess()) {
	            builder.up();
	        } else {
	            builder.down();
	        }
	        builder.withDetail("timestamp", health.getTimestamp());
        } else {
        	// should never happen
        	builder.unknown();
        }
    }

    protected abstract JwksHealth getJwksHealth();

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