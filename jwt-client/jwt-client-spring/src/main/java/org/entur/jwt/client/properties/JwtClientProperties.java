package org.entur.jwt.client.properties;

import java.util.HashMap;
import java.util.Map;

public class JwtClientProperties {

    protected JwtHealthIndicator healthIndicator = new JwtHealthIndicator();

    protected Map<String, Auth0JwtClientProperties> auth0 = new HashMap<>();

    protected Map<String, KeycloakJwtClientProperties> keycloak = new HashMap<>();

    protected Integer connectTimeout;
    protected Integer readTimeout;

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

    public Integer getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(Integer connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public Integer getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(Integer readTimeout) {
        this.readTimeout = readTimeout;
    }
}
