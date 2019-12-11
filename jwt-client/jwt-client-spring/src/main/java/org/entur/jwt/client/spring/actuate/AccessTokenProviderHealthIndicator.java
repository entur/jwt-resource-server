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

    private final AccessTokenHealthProvider provider;

    public AccessTokenProviderHealthIndicator(AccessTokenHealthProvider statusProvider) {
        super();
        this.provider = statusProvider;
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) throws Exception {
        try {
            AccessTokenHealth status = provider.getHealth(true);
            if (status.isSuccess()) {
                builder.up();
            } else {
                builder.down();
            }

            builder.withDetail("timestamp", status.getTimestamp());
        } catch (AccessTokenHealthNotSupportedException e) {
            logger.error("Health checks are not supported", e);

            builder.down();
        }
    }

}