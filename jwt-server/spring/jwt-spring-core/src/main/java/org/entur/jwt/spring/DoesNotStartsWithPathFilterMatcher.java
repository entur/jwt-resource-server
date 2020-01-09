package org.entur.jwt.spring;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.util.matcher.RequestMatcher;

public class DoesNotStartsWithPathFilterMatcher implements RequestMatcher {

    private final String[] filters; // thread safe

    public DoesNotStartsWithPathFilterMatcher(List<String> paths) {
        this.filters = paths.toArray(new String[paths.size()]);
    }
    
    /**
     * 
     * Return true if the current request is NOT matches by the filter(s).
     * 
     */
    
    @Override
    public boolean matches(HttpServletRequest httpRequest) {
        return !isPath(httpRequest);
    }

    private boolean isPath(HttpServletRequest httpRequest) {
        String path = httpRequest.getServletPath();
        if (path != null) {
            for (String filter : filters) {
                if (path.startsWith(filter)) {
                    return true;
                }
            }
        }
        return false;
    }
}
