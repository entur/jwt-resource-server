package org.entur.jwt.spring.properties.jwk;

public class JwtDecoderCacheProperties {

    private boolean enabled = false;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

}
