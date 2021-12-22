package org.entur.jwt.spring.properties;

import java.util.ArrayList;
import java.util.List;

public class CorsProperties {

    private boolean enabled = true;

    private String mode = "api";

    private List<String> origins = new ArrayList<>();
    
    private List<String> methods; // null for not set

    private List<String> headers; // null for not set

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public List<String> getOrigins() {
        if (origins == null) {
            origins = new ArrayList<>();
        }
        return origins;
    }

    public void setOrigins(List<String> hosts) {
        this.origins = hosts;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public List<String> getMethods() {
        return methods;
    }

    public void setMethods(List<String> methods) {
        this.methods = methods;
    }

    public List<String> getHeaders() {
        return headers;
    }

    public void setHeaders(List<String> headers) {
        this.headers = headers;
    }

    public boolean hasHeaders() {
        return headers != null && !headers.isEmpty();
    }

    public boolean hasMethods() {
        return methods != null && !methods.isEmpty();
    }
}
