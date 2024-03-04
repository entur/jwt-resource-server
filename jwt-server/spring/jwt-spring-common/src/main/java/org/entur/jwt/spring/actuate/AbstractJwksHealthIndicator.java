package org.entur.jwt.spring.actuate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.health.AbstractHealthIndicator;
import org.springframework.boot.actuate.health.Health;

/**
 * 
 * Health indicator.
 * 
 */

public abstract class AbstractJwksHealthIndicator extends AbstractHealthIndicator {

    private static final Logger logger = LoggerFactory.getLogger(AbstractJwksHealthIndicator.class);

    private JwksHealth previousHealth;

    protected final String name;

    // do we want to log status?
    protected boolean silent;

    protected AbstractJwksHealthIndicator(String name) {
        this.name = name;
    }

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
        if(!silent) {
            if (previousHealth != null) {
                if (!previousHealth.isSuccess() && health.isSuccess()) {
                    logger.info("{} JWKs health transitioned to UP", name);
                } else if (previousHealth.isSuccess() && !health.isSuccess()) {
                    logger.warn("{} JWKs health transitioned to DOWN", name);
                }
            } else {
                if (!health.isSuccess()) {
                    logger.info("{} JWKs health initialized to DOWN", name);
                } else {
                    logger.info("{} JWKs health initialized to UP", name);
                }
            }
        }
        this.previousHealth = health;
    }

    public String getName() {
        return name;
    }
}