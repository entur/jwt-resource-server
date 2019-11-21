package org.entur.jwt.verifier.config;

public class JwkPreemptiveCacheProperties {
	
    protected boolean enabled = true;
    /** time to live, in seconds */
    protected long timeToExpires = 15;
    
	public boolean isEnabled() {
		return enabled;
	}
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	public long getTimeToExpires() {
		return timeToExpires;
	}
	public void setTimeToExpires(long timeToExpires) {
		this.timeToExpires = timeToExpires;
	}

}
