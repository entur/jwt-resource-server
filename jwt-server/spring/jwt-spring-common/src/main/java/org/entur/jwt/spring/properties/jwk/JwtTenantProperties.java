package org.entur.jwt.spring.auth0.properties.jwk;

import java.util.HashMap;
import java.util.Map;

public class JwtTenantProperties {

    private boolean enabled = true;

    protected String type;
    protected String issuer;

    protected JwkLocationProperties jwk;

    protected Map<String, Object> properties = new HashMap<>();

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public JwkLocationProperties getJwk() {
        return jwk;
    }

    public void setJwk(JwkLocationProperties jwk) {
        this.jwk = jwk;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setProperties(Map<String, Object> properties) {
        this.properties = properties;
    }
    
    public Map<String, Object> getProperties() {
        return properties;
    }

}
