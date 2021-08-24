package org.entur.jwt.client.springcloud.actuate;

import org.entur.jwt.client.AccessTokenHealthProvider;
import org.entur.jwt.client.springcore.actuate.AbstractSpringAccessTokenProviderHealthIndicator;

/**
 * Health indicator that injects itself into the corresponding health endpoint.
 * <p>
 * Assuming we're checking for readiness.
 */

public class AccessTokenProviderHealthIndicator extends AbstractSpringAccessTokenProviderHealthIndicator {

    public AccessTokenProviderHealthIndicator(AccessTokenHealthProvider[] statusProviders) {
        super(statusProviders);
    }
}
