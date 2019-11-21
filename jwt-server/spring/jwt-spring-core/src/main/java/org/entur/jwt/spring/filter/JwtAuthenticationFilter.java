package org.entur.jwt.spring.filter;

import java.io.IOException;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.entur.jwt.jwk.JwksException;
import org.entur.jwt.jwk.JwksServiceException;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.entur.jwt.verifier.JwtClaimExtractor;
import org.entur.jwt.verifier.JwtException;
import org.entur.jwt.verifier.JwtServiceException;
import org.entur.jwt.verifier.JwtVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtAuthenticationFilter<T> extends OncePerRequestFilter {
    
    public static final String AUTHORIZATION = "Authorization";

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    
    private final JwtVerifier<T> verifier;
    private final JwtAuthorityMapper<T> authorityMapper;
    private final JwtMappedDiagnosticContextMapper<T> mdcMapper;
    private final JwtClaimExtractor<T> extractor;
    private final boolean required;
    
    public JwtAuthenticationFilter(JwtVerifier<T> verifier, boolean required, JwtAuthorityMapper<T> authorityMapper, JwtMappedDiagnosticContextMapper<T> mdcMapper, JwtClaimExtractor<T> extractor) {
        this.verifier = verifier;
        this.authorityMapper = authorityMapper;
        this.mdcMapper = mdcMapper;
        this.extractor = extractor;
        this.required = required;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String header = request.getHeader(AUTHORIZATION);

        if (header != null) {
        	// if a token is present, it must be valid regardless of whether the endpoint requires autorization or not
        	T token;
        	try {
        		token = verifier.verify(header); // note: can return null
                if(token != null) {
                    List<GrantedAuthority> authorities = authorityMapper.getGrantedAuthorities(token);

                    SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken<T>(token, header, authorities, extractor));
                    
                    if(mdcMapper != null) {
    	                mdcMapper.addContext(token);
    	                try {
    	                    chain.doFilter(request,response);
    	                } finally {
    	                    mdcMapper.removeContext(token);
    	                }
                    } else {
                        chain.doFilter(request,response);
                    }
                } else {
                    log.warn("Unable to verify token");
                    response.sendError(HttpStatus.UNAUTHORIZED.value());
                }
	        } catch(JwksServiceException | JwtServiceException e) {
        		throw new JwtAuthenticationServiceUnavailableException("Unable to process token", e);
        	} catch(JwtException | JwksException e) { // assume client
        		log.info("Problem verifying token", e);
        		response.sendError(HttpStatus.UNAUTHORIZED.value());
        	}
        } else if(!required) {
            chain.doFilter(request,response);
        } else {
            log.warn("No token");
            response.sendError(HttpStatus.UNAUTHORIZED.value());
        }
    }

}
