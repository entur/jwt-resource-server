package org.entur.jwt.spring.grpc.properties;

import java.util.ArrayList;
import java.util.List;

public class GrpcServicesConfiguration {

    private boolean enabled = true;

    private List<ServiceMatcherConfiguration> services = new ArrayList<>();
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setServices(List<ServiceMatcherConfiguration> services) {
        this.services = services;
    }
    
    public List<ServiceMatcherConfiguration> getServices() {
        return services;
    }
    
    
    public boolean isActive() {
        if(enabled) {
            for (ServiceMatcherConfiguration service : services) {
                if(service.isActive()) {
                    return true;
                }
            }
        }
        return false;
    }
    
    
}
