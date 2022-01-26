package org.entur.jwt.spring;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * 
 * Support for per-tenant additional custom properties / context data
 * 
 */

public class TenantsProperties {

    private Map<String, TenantProperties> issuers = new HashMap<>();
    private Map<String, TenantProperties> ids = new HashMap<>();
    
    public void add(TenantProperties properties) {
        if(ids.put(properties.getId(), properties) != null) {
            throw new IllegalStateException();
        }
        if(issuers.put(properties.getIssuer(), properties) != null) {
            throw new IllegalStateException();
        }
    }
    
    public TenantProperties getByIssuer(String issuer) {
        return issuers.get(issuer);
    }
    public TenantProperties getById(String issuer) {
        return issuers.get(issuer);
    }
    
    public Collection<TenantProperties> getAll() {
        return issuers.values(); 
    }
}
