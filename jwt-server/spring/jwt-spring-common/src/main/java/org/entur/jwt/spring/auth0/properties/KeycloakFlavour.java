package org.entur.jwt.spring.auth0.properties;

public class KeycloakFlavour {

    private boolean enabled = true;

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

}
