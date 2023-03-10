package org.entur.jwt.spring.config;

import java.io.IOException;

import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtMappedDiagnosticContextFilter extends OncePerRequestFilter {

    private final JwtMappedDiagnosticContextMapper mdcMapper;

    public JwtMappedDiagnosticContextFilter(JwtMappedDiagnosticContextMapper mdcMapper) {
		this.mdcMapper = mdcMapper;
	}
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
    	
    	Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    	if(authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
    		Jwt token = jwtAuthenticationToken.getToken();
            mdcMapper.addContext(token);
            try {
                chain.doFilter(request, response);
            } finally {
                mdcMapper.removeContext(token);
            }
    	} else {
    		chain.doFilter(request,response);
    	}
    }

}
