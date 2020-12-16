package org.entur.jwt.spring.grpc.properties;

public class ServiceMethodMatcher {

    private String service;
    
    private String method;

    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }
    
    
    
}
