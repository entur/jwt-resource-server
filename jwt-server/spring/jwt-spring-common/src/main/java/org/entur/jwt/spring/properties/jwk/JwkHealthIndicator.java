package org.entur.jwt.spring.properties.jwk;

public class JwkHealthIndicator {

    protected boolean enabled = true;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

}
