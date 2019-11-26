package org.entur.jwt.spring;

import java.io.IOException;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 
 * Filter for denying requests without a token at the earliest possible stage. Contains a path filter, so that
 * services like actuator optionally can be excluded.
 * 
 */

public final class JwtFilter implements Filter {

	private final String[] filters; // thread safe

	public JwtFilter(List<String> paths) {
		this.filters = paths.toArray(new String[paths.size()]);
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

		HttpServletRequest httpRequest = (HttpServletRequest) request;

		String header = httpRequest.getHeader("Authorization");
		if(header != null && header.startsWith("Bearer ")) {
			chain.doFilter(httpRequest, response);
		} else if(isPath(httpRequest)) {
			chain.doFilter(httpRequest, response);
		} else {
			HttpServletResponse httpResponse = (HttpServletResponse) response;

			httpResponse.setStatus(401);
		}
	}

	private boolean isPath(HttpServletRequest httpRequest) {
		String path = httpRequest.getServletPath(); 
		if(path != null) {
			for(String filter : filters) {
				if(path.startsWith(filter)) {
					return true;
				}
			}
		}
		return false;
	}
}
