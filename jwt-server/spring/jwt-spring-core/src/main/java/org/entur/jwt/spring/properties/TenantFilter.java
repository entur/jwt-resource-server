package org.entur.jwt.spring.properties;

import java.util.ArrayList;
import java.util.List;

public class TenantFilter {

    private List<String> keys = new ArrayList<>();
    
    public List<String> getKeys() {
        return keys;
    }
    
    public void setKeys(List<String> keys) {
        this.keys = keys;
    }

    public boolean isEmpty() {
        return keys == null || keys.isEmpty();
    }
}
