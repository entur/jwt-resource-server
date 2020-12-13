package org.entur.jwt.spring;

import java.util.Map;

public class TenantProperties {

    private String id;
    private String issuer;
    private Map<String, Object> properties;

    public TenantProperties(String id, String issuer, Map<String, Object> properties) {
        super();
        this.id = id;
        this.issuer = issuer;
        this.properties = properties;
    }

    public String getId() {
        return id;
    }

    public String getIssuer() {
        return issuer;
    }

    public Map<String, Object> getProperties() {
        return properties;
    }
    
    public Object getProperty(String key) {
        return properties.get(key);
    }
    
}
