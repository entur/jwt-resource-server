package org.entur.jwt.spring.properties;

/**
 * 
 * Note that Ant matchers are stricter than MVC matchers.
 *
 */

public class PermitAll {

    private boolean enabled = true;

    private MatcherConfiguration mvcMatcher = new MatcherConfiguration();
    private MatcherConfiguration antMatcher = new MatcherConfiguration();
    
    public void setMvcMatcher(MatcherConfiguration mvcMatchers) {
        this.mvcMatcher = mvcMatchers;
    }
    
    public MatcherConfiguration getMvcMatcher() {
        return mvcMatcher;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public boolean isActive() {
        return enabled && (mvcMatcher.isActive() || antMatcher.isActive());
    }
    
    public void setAntMatcher(MatcherConfiguration antMatcher) {
        this.antMatcher = antMatcher;
    }
    
    public MatcherConfiguration getAntMatcher() {
        return antMatcher;
    }
}
