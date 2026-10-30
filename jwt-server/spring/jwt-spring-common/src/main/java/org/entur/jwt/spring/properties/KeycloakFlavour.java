package org.entur.jwt.spring.properties;

public class KeycloakFlavour {

    private boolean enabled = true;

    /**
     * Client id (i.e. key in the access-token claim {@code resource_access}) of the client whose roles are mapped to
     * authorities (with prefix {@code ROLE_}). Normally the client id of this resource server. If not set, no client
     * roles are mapped.
     */
    private String clientId;

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

}
