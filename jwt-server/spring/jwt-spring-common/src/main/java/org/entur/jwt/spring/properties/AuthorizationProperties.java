package org.entur.jwt.spring.properties;
/**
 * Basic configuration for spring security authorization filter.
 * <br><br>
 * By default all calls must be fully authenticated. Exceptions must be explicitly specified, included for the actuator.
 *
 */

public class AuthorizationProperties {

    private boolean enabled = true;
    
    private PermitAll permitAll = new PermitAll();
    
    public void setPermitAll(PermitAll permitAll) {
        this.permitAll = permitAll;
    }
    
    public PermitAll getPermitAll() {
        return permitAll;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
}
