package org.entur.jwt.spring.properties;

import java.util.ArrayList;
import java.util.List;

import org.springframework.http.HttpMethod;

public class HttpMethodMatcher {

    private boolean enabled = true;
    
    private List<String> patterns = new ArrayList<>();

    private final HttpMethod verb;
    
    public HttpMethodMatcher(HttpMethod verb) {
        super();
        this.verb = verb;
    }

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
    
    public boolean isActive() {
        return enabled && !patterns.isEmpty();
    }

    public HttpMethod getVerb() {
        return verb;
    }
    
    public String[] getPatternsAsArray() {
        return patterns.toArray(new String[patterns.size()]);
    }

}
