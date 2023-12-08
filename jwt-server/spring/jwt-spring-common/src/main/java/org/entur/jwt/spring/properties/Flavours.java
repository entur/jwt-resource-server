package org.entur.jwt.spring.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "entur.jwt.flavours")
public class Flavours {

    private boolean enabled = true;

    private Auth0Flavour auth0 = new Auth0Flavour();

    private KeycloakFlavour keycloak = new KeycloakFlavour();

    public Auth0Flavour getAuth0() {
        return auth0;
    }

    public void setAuth0(Auth0Flavour auth0) {
        this.auth0 = auth0;
    }

    public KeycloakFlavour getKeycloak() {
        return keycloak;
    }

    public void setKeycloak(KeycloakFlavour keycloak) {
        this.keycloak = keycloak;
    }


    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }
}
