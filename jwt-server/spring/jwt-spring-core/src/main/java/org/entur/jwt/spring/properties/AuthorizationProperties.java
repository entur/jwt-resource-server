package org.entur.jwt.spring.properties;
/**
 * 
 * By default all calls must be fully authenticated. Exceptions must be explicitly specified, included for the actuator.
 *
 */

public class AuthorizationProperties {

    private PermitAll permitAll = new PermitAll();
    
    public void setPermitAll(PermitAll permitAll) {
        this.permitAll = permitAll;
    }
    
    public PermitAll getPermitAll() {
        return permitAll;
    }

}
