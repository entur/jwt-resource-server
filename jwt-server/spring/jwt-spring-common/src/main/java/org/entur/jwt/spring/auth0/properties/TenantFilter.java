package org.entur.jwt.spring.auth0.properties;

import java.util.ArrayList;
import java.util.List;

public class TenantFilter {

    private List<String> ids = new ArrayList<>();
    
    public List<String> getIds() {
        return ids;
    }
    
    public void setIds(List<String> keys) {
        this.ids = keys;
    }

    public boolean isEmpty() {
        return ids == null || ids.isEmpty();
    }
}
