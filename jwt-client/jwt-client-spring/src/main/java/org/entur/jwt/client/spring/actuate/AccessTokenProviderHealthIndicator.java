package org.entur.jwt.client.spring.actuate;

import org.entur.jwt.client.AccessTokenHealth;
import org.entur.jwt.client.AccessTokenHealthNotSupportedException;
import org.entur.jwt.client.AccessTokenHealthProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.health.AbstractHealthIndicator;
import org.springframework.boot.actuate.health.Health;

/**
 * 
 * Health indicator that injects itself into the corresponding health endpoint.
 * 
 * Assuming we're checking for readiness.
 * 
 */

public class AccessTokenProviderHealthIndicator extends AbstractHealthIndicator {

    protected static final Logger logger = LoggerFactory.getLogger(AccessTokenProviderHealthIndicator.class);

    private final AccessTokenHealthProvider[] providers;
    
    private Boolean previousHealthSuccess;

    public AccessTokenProviderHealthIndicator(AccessTokenHealthProvider[] statusProviders) {
        super();
        this.providers = statusProviders;
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) throws Exception {
        try {
            // iterate over clients, and record the min / max timestamps.
            boolean success = true;
            long mostRecentTimestamp = Long.MIN_VALUE;
            long leastRecentTimestamp = Long.MAX_VALUE;
            
            for(AccessTokenHealthProvider provider : providers) {
                AccessTokenHealth status = provider.getHealth(true);
                if (!status.isSuccess()) {
                    success = false;
                }
                
                if(mostRecentTimestamp < status.getTimestamp()) {
                    mostRecentTimestamp = status.getTimestamp();
                }
                if(leastRecentTimestamp > status.getTimestamp()) {
                    leastRecentTimestamp = status.getTimestamp();
                }
            }

            long time = System.currentTimeMillis();
            if(mostRecentTimestamp != Long.MIN_VALUE) {
                builder.withDetail("youngestTimestamp", (time - mostRecentTimestamp) / 1000);
            } 
            if(leastRecentTimestamp != Long.MAX_VALUE) {
                builder.withDetail("oldestTimestamp", (time - leastRecentTimestamp) / 1000);
            }
            
            Boolean previousSuccess = this.previousHealthSuccess; // defensive copy
            if(previousSuccess != null) {
                if(!previousSuccess && success) {
                    logger.info("Access-token-provider health transitioned to UP");
                } else if(previousSuccess && !success) {
                    logger.warn("Access-token-provider health transitioned to DOWN");
                }
            } else {
                if(!success) {
                    logger.warn("Access-token-provider health initialized to DOWN");
                } else {
                    logger.info("Access-token-provider health initialized to UP");
                }
            }
            this.previousHealthSuccess = success;

            if (success) {
                builder.up();
            } else {
                builder.down();
            }
        } catch (AccessTokenHealthNotSupportedException e) {
            logger.error("Health checks are unexpectedly not supported", e);

            builder.unknown();
        }
    }

}