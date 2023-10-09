package org.entur.jwt.spring.properties;

/**
 * 
 * Note that Ant matchers are stricter than MVC matchers.
 *
 */

public class PermitAll {

    private boolean enabled = true;

    private MatcherConfiguration matcher = new MatcherConfiguration();

    public void setMatcher(MatcherConfiguration mvcMatchers) {
        this.matcher = mvcMatchers;
    }
    
    public MatcherConfiguration getMatcher() {
        return matcher;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public boolean isActive() {
        return enabled && (matcher.isActive());
    }

}
