package org.entur.jwt.spring.filter;

import java.io.IOException;
import java.io.Serializable;
import java.util.List;
import java.util.Map;

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
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

public class JwtAuthenticationFilter<T> extends OncePerRequestFilter {

    public static final String AUTHORIZATION = "Authorization";
    public static final String BEARER = "Bearer ";

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtVerifier<T> verifier;
    private final JwtAuthorityMapper<T> authorityMapper;
    private final JwtMappedDiagnosticContextMapper<T> mdcMapper;
    private final JwtClaimExtractor<T> extractor;
    private final boolean required;
    private final HandlerExceptionResolver handlerExceptionResolver;
    private final JwtDetailsMapper detailsMapper;
    private final JwtPrincipalMapper principalMapper;

    public JwtAuthenticationFilter(JwtVerifier<T> verifier, boolean required, JwtAuthorityMapper<T> authorityMapper, JwtMappedDiagnosticContextMapper<T> mdcMapper, JwtClaimExtractor<T> extractor, HandlerExceptionResolver handlerExceptionResolver, JwtPrincipalMapper principalMapper, JwtDetailsMapper detailsMapper) {
        this.verifier = verifier;
        this.authorityMapper = authorityMapper;
        this.mdcMapper = mdcMapper;
        this.extractor = extractor;
        this.required = required;
        this.handlerExceptionResolver = handlerExceptionResolver;
        this.principalMapper = principalMapper;
        this.detailsMapper = detailsMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String header = request.getHeader(AUTHORIZATION);

        if (header != null && header.startsWith(BEARER)) {
            String bearerToken = header.substring(BEARER.length());
            // if a token is present, it must be valid regardless of whether the endpoint
            // requires authorization or not
            T token;
            try {

                token = verifier.verify(bearerToken); // note: can return null
                if (token != null) {
                    List<GrantedAuthority> authorities = authorityMapper.getGrantedAuthorities(token);

                    Map<String, Object> claims = extractor.getClaims(token);

                    Serializable details = detailsMapper.getDetails(request, claims);
                    Serializable principal = principalMapper.getPrincipal(claims);

                    SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(claims, bearerToken, authorities, principal, details));

                    if (mdcMapper != null) {
                        mdcMapper.addContext(token);
                        try {
                            chain.doFilter(request, response);
                        } finally {
                            mdcMapper.removeContext(token);
                        }
                    } else {
                        chain.doFilter(request, response);
                    }
                } else {
                    log.warn("Unable to verify token");
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    handlerExceptionResolver.resolveException(request, response, null, new BadCredentialsException("Unable to verify token"));
                }
            } catch (JwksServiceException | JwtServiceException e) {
                response.setStatus(HttpStatus.SERVICE_UNAVAILABLE.value());
                handlerExceptionResolver.resolveException(request, response, null, new JwtAuthenticationServiceUnavailableException("Unable to process token", e));
            } catch (JwtException | JwksException e) { // assume client
                log.info("Problem verifying token", e);
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                handlerExceptionResolver.resolveException(request, response, null, new BadCredentialsException("Unable to verify token", e));
            }
        } else if (!required) {
            chain.doFilter(request, response);
        } else {
            log.warn("Authentication is required, however there was no bearer token");
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            handlerExceptionResolver.resolveException(request, response, null, new BadCredentialsException("Expected token"));
        }
    }

}
