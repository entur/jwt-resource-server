package org.entur.jwt.spring.properties.jwk;

public class JwtEagerRefresh {
    // note: no kind of retrying scheme is implemented if the scheduled refresh fails;
    // let the health-checks must handle that situation,
    // and if not fall back to on-demand refresh
    
    private boolean enabled = false;
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
}
