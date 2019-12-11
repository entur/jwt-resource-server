package org.entur.jwt.client.properties;

public class KeycloakJwtClientProperties extends AbstractJwtClientProperties {

    protected String realm;

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }
}