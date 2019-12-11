package org.entur.jwt.jwk;

public class JwksHealth {

    private final long timestamp;
    private final boolean success;

    public JwksHealth(long timestamp, boolean success) {
        super();
        this.success = success;
        this.timestamp = timestamp;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public boolean isSuccess() {
        return success;
    }
}