package org.entur.jwt.spring.grpc.properties;

public class GrpcException {

    private String name;
    private GrpcExceptionLog log = new GrpcExceptionLog();

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public GrpcExceptionLog getLog() {
        return log;
    }

    public void setLog(GrpcExceptionLog log) {
        this.log = log;
    }
}
