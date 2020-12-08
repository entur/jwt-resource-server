package org.entur.jwt.spring.grpc.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 
 * Note that Ant matchers are stricter than MVC matchers.
 *
 */

@ConfigurationProperties(prefix = "entur.authorization.permit-all")
public class GrpcPermitAll {

    private boolean enabled = true;

    private GrpcServicesConfiguration grpc = new GrpcServicesConfiguration();
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public boolean isActive() {
        return enabled && grpc.isActive();
    }

    public GrpcServicesConfiguration getGrpc() {
		return grpc;
	}
    
    public void setGrpc(GrpcServicesConfiguration grpc) {
		this.grpc = grpc;
	}

}
