package org.entur.jwt.client.properties;

import java.util.HashMap;
import java.util.Map;

public class AbstractSpringJwtClientProperties {

    protected JwtHealthIndicator healthIndicator = new JwtHealthIndicator();

    protected Map<String, Auth0JwtClientProperties> auth0 = new HashMap<>();

    protected Map<String, KeycloakJwtClientProperties> keycloak = new HashMap<>();

    protected long connectTimeout = 15; // seconds
    protected long readTimeout = 15; // seconds

    public void setHealthIndicator(JwtHealthIndicator healthIndicator) {
        this.healthIndicator = healthIndicator;
    }

    public JwtHealthIndicator getHealthIndicator() {
        return healthIndicator;
    }

    public Map<String, Auth0JwtClientProperties> getAuth0() {
        return auth0;
    }

    public Map<String, KeycloakJwtClientProperties> getKeycloak() {
        return keycloak;
    }

    public void setAuth0(Map<String, Auth0JwtClientProperties> auth0) {
        this.auth0 = auth0;
    }

    public void setKeycloak(Map<String, KeycloakJwtClientProperties> keycloak) {
        this.keycloak = keycloak;
    }

    public long getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(long connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public long getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(long readTimeout) {
        this.readTimeout = readTimeout;
    }
}
