package org.entur.jwt.client.spring.actuate;

import org.entur.jwt.client.AccessTokenHealth;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.health.contributor.AbstractHealthIndicator;
import org.springframework.boot.health.contributor.Health;

/**
 * 
 * Health indicator.
 * 
 */

public abstract class AbstractJwtHealthIndicator extends AbstractHealthIndicator {

    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractJwtHealthIndicator.class);

    private AccessTokenHealth previousHealth;

    protected final String name;

    protected AbstractJwtHealthIndicator(String name) {
        this.name = name;
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) throws Exception {

        AccessTokenHealth health = refreshHealth();
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

    protected abstract AccessTokenHealth refreshHealth();

    protected void logInitialOrChangedState(AccessTokenHealth health) {
        AccessTokenHealth previousHealth = this.previousHealth; // defensive copy
        if (previousHealth != null) {
            if (!previousHealth.isSuccess() && health.isSuccess()) {
                if(LOGGER.isInfoEnabled()) LOGGER.info("{} JWT health transitioned to UP", name);
            } else if (previousHealth.isSuccess() && !health.isSuccess()) {
                if(LOGGER.isInfoEnabled()) LOGGER.warn("{} JWT health transitioned to DOWN", name);
            }
        } else {
            if (!health.isSuccess()) {
                if(LOGGER.isInfoEnabled()) LOGGER.info("{} JWT health initialized to DOWN", name);
            } else {
                if(LOGGER.isInfoEnabled()) LOGGER.info("{} JWT health initialized to UP", name);
            }
        }
        this.previousHealth = health;
    }

    public String getName() {
        return name;
    }
}