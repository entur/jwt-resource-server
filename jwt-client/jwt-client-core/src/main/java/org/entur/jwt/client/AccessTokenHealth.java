package org.entur.jwt.client;

public class AccessTokenHealth {

    private final long timestamp;
    private final boolean success;

    public AccessTokenHealth(long timestamp, boolean success) {
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