package org.entur.jwt.spring.properties.jwk;

public class JwkRateLimitProperties {

    protected boolean enabled = true;

    /** tokens per second */
    protected double refillRate = 0.1d;

    public double getRefillRate() {
        return refillRate;
    }

    public void setRefillRate(double refillRate) {
        this.refillRate = refillRate;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

}
