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
 */

public class AccessTokenProviderHealthIndicator extends AbstractHealthIndicator {

    protected static final Logger logger = LoggerFactory.getLogger(AccessTokenProviderHealthIndicator.class);

    private final AccessTokenHealthProvider[] providers;

    public AccessTokenProviderHealthIndicator(AccessTokenHealthProvider[] statusProviders) {
        super();
        this.providers = statusProviders;
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) throws Exception {
        try {
            
            // iterate over clients, and record the min / max timestamps.
            boolean down = false;
            long mostRecentTimestamp = Long.MIN_VALUE;
            long leastRecentTimestamp = Long.MAX_VALUE;
            
            for(AccessTokenHealthProvider provider : providers) {
                AccessTokenHealth status = provider.getHealth(true);
                if (!status.isSuccess()) {
                    down = true;
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

            if (down) {
                builder.down();
            } else {
                builder.up();
            }
        } catch (AccessTokenHealthNotSupportedException e) {
            logger.error("Health checks are not supported", e);

            builder.unknown();
        }
    }

}