package org.entur.jwt.spring.properties;

/**
 *
 * Note that Ant matchers are stricter than MVC matchers.
 *
 */

public class PermitAll {

    private boolean enabled = true;

    private MatcherConfiguration pathMatcher = new MatcherConfiguration();

    public MatcherConfiguration getPathMatcher() {
        return pathMatcher;
    }

    public void setPathMatcher(MatcherConfiguration pathMatcher) {
        this.pathMatcher = pathMatcher;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public boolean isActive() {
        return enabled && (pathMatcher.isActive());
    }


}
