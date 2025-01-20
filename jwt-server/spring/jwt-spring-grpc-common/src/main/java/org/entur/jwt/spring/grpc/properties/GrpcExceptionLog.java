package org.entur.jwt.spring.grpc.properties;

public class GrpcExceptionLog {

    private String level = "info";
    private boolean stackTrace = true;

    public String getLevel() {
        return level;
    }

    public void setLevel(String level) {
        this.level = level;
    }

    public boolean isStackTrace() {
        return stackTrace;
    }

    public void setStackTrace(boolean stackTrace) {
        this.stackTrace = stackTrace;
    }
}
