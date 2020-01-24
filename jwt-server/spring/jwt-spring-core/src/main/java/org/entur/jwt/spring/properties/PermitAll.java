package org.entur.jwt.spring.properties;

// TODO possibly add ant and path matchers as well, but we prefer mvc matchers for now
public class PermitAll {

    private boolean enabled = true;

    private MatcherConfiguration mvcMatcher = new MatcherConfiguration();
    
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
        return enabled && mvcMatcher.isActive();
    }
}
