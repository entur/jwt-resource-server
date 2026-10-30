
package org.entur.jwt.client.properties;

import org.entur.jwt.client.keycloak.KeycloakClientCredentialsBuilder;

public class KeycloakJwtClientProperties extends AbstractJwtClientProperties {

    protected String realm;

    protected String contextPath = KeycloakClientCredentialsBuilder.DEFAULT_CONTEXT_PATH;

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public String getContextPath() {
        return contextPath;
    }

    public void setContextPath(String contextPath) {
        this.contextPath = contextPath;
    }
}