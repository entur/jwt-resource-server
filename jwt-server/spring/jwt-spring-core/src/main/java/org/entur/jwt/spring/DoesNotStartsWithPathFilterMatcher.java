package org.entur.jwt.spring;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.util.matcher.RequestMatcher;

public class DoesNotStartsWithPathFilterMatcher implements RequestMatcher {

    private final String[] filters; // thread safe

    public DoesNotStartsWithPathFilterMatcher(List<String> paths) {
        this.filters = paths.toArray(new String[paths.size()]);
    }
    
    @Override
    public boolean matches(HttpServletRequest httpRequest) {
        boolean mustBeAuthenticated = !isPath(httpRequest);
        return mustBeAuthenticated;
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
