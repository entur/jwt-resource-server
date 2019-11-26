package org.entur.jwt.client.properties;

public class JwtClientCache {

	private boolean enabled = true;

	/** Minimum number of seconds left before the returned (cached) token expires */ 
	private int minimumTimeToLive = 15; // in seconds

	/** Number of seconds to wait for a token, if it must be refreshed */
	private int refreshTimeOut = 15; // cache refresh timeout in seconds

	private PreemptiveRefresh preemptiveRefresh = new PreemptiveRefresh();

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public int getMinimumTimeToLive() {
		return minimumTimeToLive;
	}

	public void setMinimumTimeToLive(int minimumTimeToLive) {
		this.minimumTimeToLive = minimumTimeToLive;
	}

	public PreemptiveRefresh getPreemptiveRefresh() {
		return preemptiveRefresh;
	}

	public void setPreemptiveRefresh(PreemptiveRefresh preemptiveRefresh) {
		this.preemptiveRefresh = preemptiveRefresh;
	}

	public int getRefreshTimeOut() {
		return refreshTimeOut;
	}

	public void setRefreshTimeOut(int refreshTimeOut) {
		this.refreshTimeOut = refreshTimeOut;
	}
}
