package org.entur.jwt.spring.properties;

import java.util.ArrayList;
import java.util.List;

public class MatcherConfiguration {

    private boolean enabled = true;

    private MethodMatcherConfiguration method = new MethodMatcherConfiguration();

    private List<String> patterns = new ArrayList<>();

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setPatterns(List<String> patterns) {
        this.patterns = patterns;
    }
    
    public List<String> getPatterns() {
        return patterns;
    }
    
    public void setMethod(MethodMatcherConfiguration httpMethod) {
        this.method = httpMethod;
    }
    
    public MethodMatcherConfiguration getMethod() {
        return method;
    }
    
    public String[] getPatternsAsArray() {
        return patterns.toArray(new String[patterns.size()]);
    }

    public boolean isActive() {
        return enabled && (!patterns.isEmpty() || method.isActive());
    }

    public boolean hasPatterns() {
        return !patterns.isEmpty();
    }
    
}
