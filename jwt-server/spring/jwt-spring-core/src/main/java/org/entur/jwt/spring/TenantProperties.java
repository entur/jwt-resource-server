package org.entur.jwt.spring;

import java.util.Map;

public class TenantProperties {

    private String name;
    private String issuer;
    private Map<String, Object> properties;

    public TenantProperties(String name, String issuer, Map<String, Object> properties) {
        super();
        this.name = name;
        this.issuer = issuer;
        this.properties = properties;
    }

    public String getName() {
        return name;
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
