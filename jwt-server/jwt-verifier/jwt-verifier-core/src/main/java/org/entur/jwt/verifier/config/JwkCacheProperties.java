package org.entur.jwt.verifier.config;

import java.util.concurrent.TimeUnit;

public class JwkCacheProperties {

	protected boolean enabled = true;
	protected long timeToLive = TimeUnit.HOURS.toSeconds(1);
	protected long refreshTimeout = 15; // seconds

	protected JwkPreemptiveCacheProperties preemptive = new JwkPreemptiveCacheProperties();

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public long getTimeToLive() {
		return timeToLive;
	}

	public void setTimeToLive(long timeToLive) {
		this.timeToLive = timeToLive;
	}

	public long getRefreshTimeout() {
		return refreshTimeout;
	}

	public void setRefreshTimeout(long refreshTimeout) {
		this.refreshTimeout = refreshTimeout;
	}

	public JwkPreemptiveCacheProperties getPreemptive() {
		return preemptive;
	}

	public void setPreemptive(JwkPreemptiveCacheProperties preemptive) {
		this.preemptive = preemptive;
	}


}
