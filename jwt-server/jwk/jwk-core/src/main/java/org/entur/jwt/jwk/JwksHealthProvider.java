package org.entur.jwt.jwk;

public interface JwksHealthProvider {

	/**
	 * Get health. An implementation is expected to refresh the health status 
	 * if there is no current status, or if the last status was unsuccessful. 
	 * 
	 * @param refresh true if the provider should refresh a missing or bad health status before returning.
	 * @throws JwksHealthNotSupportedException if operation not supported
	 * @return health status.
	 */

	default JwksHealth getHealth(boolean refresh) {
		throw new JwksHealthNotSupportedException("Provider " + getClass().getName() + " does not support health requests");
	}

}
