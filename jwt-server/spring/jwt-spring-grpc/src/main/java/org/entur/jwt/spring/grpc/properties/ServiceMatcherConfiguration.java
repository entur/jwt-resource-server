package org.entur.jwt.spring.grpc.properties;

import java.util.ArrayList;
import java.util.List;

public class ServiceMatcherConfiguration {

    private boolean enabled = true;

    private String name;

    private List<String> methods = new ArrayList<>();

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public boolean isActive() {
        return enabled && !methods.isEmpty();
    }

    public boolean hasPatterns() {
        return !methods.isEmpty();
    }
    
    public void setName(String name) {
		this.name = name;
	}
    
    public String getName() {
		return name;
	}
    
    public List<String> getMethods() {
		return methods;
	}
    public void setMethods(List<String> methods) {
		this.methods = methods;
	}
}
