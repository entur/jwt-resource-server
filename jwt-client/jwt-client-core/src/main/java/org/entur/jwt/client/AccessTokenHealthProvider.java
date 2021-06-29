package org.entur.jwt.client;

public interface AccessTokenHealthProvider {

    /**
     * Get health. An implementation is expected to refresh the health status if
     * there is no current status, or if the last status was unsuccessful.
     * 
     * @param refresh true if the provider (optionally) can refresh the state before returning (typically if the health is missing or bad)
     * @throws AccessTokenHealthNotSupportedException if operation is not supported
     * @return health status, or null if none is available.
     */

    // implementation note: this might have returned a list, but we really do not
    // want to create a lot of status objects for each provider in the chain
    default AccessTokenHealth getHealth(boolean refresh) {
        throw new AccessTokenHealthNotSupportedException("Provider " + getClass().getName() + " does not support health requests");
    }
    
    boolean supportsHealth();
}
