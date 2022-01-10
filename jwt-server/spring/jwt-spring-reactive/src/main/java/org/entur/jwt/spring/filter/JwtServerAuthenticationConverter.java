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
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

public class JwtServerAuthenticationConverter<T> implements ServerAuthenticationConverter {

    public static final String BEARER = "Bearer ";

    private static final Logger log = LoggerFactory.getLogger(JwtServerAuthenticationConverter.class);

    private final JwtVerifier<T> verifier;
    private final JwtAuthorityMapper<T> authorityMapper;
    private final JwtMappedDiagnosticContextMapper<T> mdcMapper;
    private final JwtClaimExtractor<T> extractor;
    private final boolean required;
    private final JwtDetailsMapper detailsMapper;
    private final JwtPrincipalMapper principalMapper;

    public JwtServerAuthenticationConverter(JwtVerifier<T> verifier, JwtAuthorityMapper<T> authorityMapper, JwtMappedDiagnosticContextMapper<T> mdcMapper, JwtClaimExtractor<T> extractor, boolean required, JwtDetailsMapper detailsMapper, JwtPrincipalMapper principalMapper) {
        this.verifier = verifier;
        this.authorityMapper = authorityMapper;
        this.mdcMapper = mdcMapper;
        this.extractor = extractor;
        this.required = required;
        this.detailsMapper = detailsMapper;
        this.principalMapper = principalMapper;
    }

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        return Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
            .switchIfEmpty(Mono.defer(() -> {
                if (!required) return Mono.empty();

                throw new BadCredentialsException("Expected token");
            }))
            .mapNotNull(authHeader -> {
                    String bearerToken = authHeader.substring(BEARER.length());

                    try {
                        T token = verifier.verify(bearerToken); // note: can return null

                        if (token != null) {
                            List<GrantedAuthority> authorities = authorityMapper.getGrantedAuthorities(token);

                            Map<String, Object> claims = extractor.getClaims(token);

                            Serializable details = detailsMapper.getDetails(exchange.getRequest(), claims);
                            Serializable principal = principalMapper.getPrincipal(claims);

                            Authentication jwtToken = new JwtAuthenticationToken(claims, bearerToken, authorities, principal, details);

                            if (mdcMapper != null) {
                                mdcMapper.addContext(token);
                                try {
                                    return (jwtToken);
                                } finally {
                                    mdcMapper.removeContext(token);
                                }
                            }

                            return (jwtToken);
                        } else {
                            // do not use a high log level, assume garbage request from the internet
                            log.debug("Unable to verify token");

                            throw new BadCredentialsException("Unable to verify token");
                        }

                    } catch (JwtClientException | JwksClientException e) { // assume client misconfiguration
                        log.debug("JWT verification failed due to {}", e.getMessage());

                        throw new BadCredentialsException("Unable to verify token", e);
                    } catch (JwksException | JwtException e) { // assume server issue
                        // technically we should only see JwksServiceException or JwtServiceException here
                        // but use superclass to catch all
                        log.warn("Unable to process token", e);

                        throw new JwtAuthenticationServiceUnavailableException("Unable to process token", e);
                    }
            });
    }

}
