package org.entur.jwt.verifier.config;

public class JwkRateLimitProperties {

    protected boolean enabled = true;

    protected long bucketSize = 10;

    /** tokens per second */
    protected double refillRate = 0.1d;

    public long getBucketSize() {
        return bucketSize;
    }

    public void setBucketSize(long bucketSize) {
        this.bucketSize = bucketSize;
    }

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
