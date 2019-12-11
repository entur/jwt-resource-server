package org.entur.jwt.spring.properties;

import java.util.ArrayList;
import java.util.List;

public class CorsProperties {

    private boolean enabled = true;

    private String mode = "api";

    private List<String> hosts = new ArrayList<>();

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public List<String> getHosts() {
        if (hosts == null) {
            hosts = new ArrayList<>();
        }
        return hosts;
    }

    public void setHosts(List<String> hosts) {
        this.hosts = hosts;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }
}
