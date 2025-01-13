package org.entur.jwt.client.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.Map;

@ConfigurationProperties(prefix = "entur.jwt.clients")
public class JwtClientProperties {

    protected Map<String, Auth0JwtClientProperties> auth0 = new HashMap<>();

    protected Map<String, KeycloakJwtClientProperties> keycloak = new HashMap<>();

    protected Map<String, GenericJwtClientProperties> generic = new HashMap<>();

    protected int connectTimeout = 15; // seconds
    protected int readTimeout = 15; // seconds

    public Map<String, Auth0JwtClientProperties> getAuth0() {
        return auth0;
    }
    
    public Map<String, KeycloakJwtClientProperties> getKeycloak() {
        return keycloak;
    }

    public Map<String, GenericJwtClientProperties> getGeneric() {
        return generic;
    }
    
    public void setAuth0(Map<String, Auth0JwtClientProperties> auth0) {
        this.auth0 = auth0;
    }
    
    public void setKeycloak(Map<String, KeycloakJwtClientProperties> keycloak) {
        this.keycloak = keycloak;
    }

    public void setGeneric(Map<String, GenericJwtClientProperties> generic) {
        this.generic = generic;
    }

    public int getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(int connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public int getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(int readTimeout) {
        this.readTimeout = readTimeout;
    }
}
