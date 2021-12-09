package org.entur.jwt.spring.filter;

import org.entur.jwt.jwk.JwksClientException;
import org.entur.jwt.jwk.JwksException;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.entur.jwt.verifier.JwtClaimExtractor;
import org.entur.jwt.verifier.JwtClientException;
import org.entur.jwt.verifier.JwtException;
import org.entur.jwt.verifier.JwtVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.reactive.HandlerAdapter;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

public class JwtAuthenticationFilter<T> implements WebFilter {

    public static final String AUTHORIZATION = "Authorization";
    public static final String BEARER = "Bearer ";

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtVerifier<T> verifier;
    private final JwtAuthorityMapper<T> authorityMapper;
    private final JwtMappedDiagnosticContextMapper<T> mdcMapper;
    private final JwtClaimExtractor<T> extractor;
    private final boolean required;
    private final HandlerAdapter handlerAdapter;
    private final JwtDetailsMapper detailsMapper;
    private final JwtPrincipalMapper principalMapper;

    public JwtAuthenticationFilter(JwtVerifier<T> verifier, boolean required, JwtAuthorityMapper<T> authorityMapper, JwtMappedDiagnosticContextMapper<T> mdcMapper, JwtClaimExtractor<T> extractor, HandlerAdapter handlerAdapter, JwtPrincipalMapper principalMapper, JwtDetailsMapper detailsMapper) {
        this.verifier = verifier;
        this.authorityMapper = authorityMapper;
        this.mdcMapper = mdcMapper;
        this.extractor = extractor;
        this.required = required;
        this.handlerAdapter = handlerAdapter;
        this.principalMapper = principalMapper;
        this.detailsMapper = detailsMapper;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String header = exchange.getRequest().getHeaders().get(AUTHORIZATION).get(0);

        if (header != null) {
            if(!header.startsWith(BEARER)) {
                // assume garbage from the internet
                log.debug("Invalid authorization header type");
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                handlerAdapter.handle(exchange, new BadCredentialsException("Invalid authorization header type"));
                return Mono.empty();
            }

            doFilterInternalForBearerToken(exchange, chain, header);
        } else if (!required) {
            chain.filter(exchange);
        } else {
            log.debug("Authentication is required, however there was no bearer token");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            handlerAdapter.handle(exchange, new BadCredentialsException("Expected token"));
        }
        return Mono.empty();
    }

    protected void doFilterInternalForBearerToken(ServerWebExchange exchange, WebFilterChain chain, String header) {
        String bearerToken = header.substring(BEARER.length());
        // if a token is present, it must be valid regardless of whether the endpoint
        // requires authorization or not
        T token;
        try {

            token = verifier.verify(bearerToken); // note: can return null
            if (token != null) {
                List<GrantedAuthority> authorities = authorityMapper.getGrantedAuthorities(token);

                Map<String, Object> claims = extractor.getClaims(token);

                Serializable details = detailsMapper.getDetails(exchange.getRequest(), claims);
                Serializable principal = principalMapper.getPrincipal(claims);

                SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(claims, bearerToken, authorities, principal, details));

                if (mdcMapper != null) {
                    mdcMapper.addContext(token);
                    try {
                        chain.filter(exchange);
                    } finally {
                        mdcMapper.removeContext(token);
                    }
                } else {
                    chain.filter(exchange);
                }
            } else {
                // do not use a high log level, assume garbage request from the internet
                log.debug("Unable to verify token");

                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                handlerAdapter.handle(exchange, new BadCredentialsException("Unable to verify token"));
            }
        } catch (JwtClientException | JwksClientException e) { // assume client misconfiguration
            log.debug("JWT verification failed due to {}", e.getMessage());

            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            handlerAdapter.handle(exchange, new BadCredentialsException("Unable to verify token", e));
        } catch (JwksException | JwtException e) { // assume server issue
            // technically we should only see JwksServiceException or JwtServiceException here
            // but use superclass to catch all

            log.warn("Unable to process token", e);

            exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
            handlerAdapter.handle(exchange, new JwtAuthenticationServiceUnavailableException("Unable to process token", e));
        }
    }
}
