package org.entur.jwt.spring.config;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.entur.jwt.spring.JwtKidIssuerCache;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.Map;

public class IssuerAuthenticationManagerResolver implements ReactiveAuthenticationManagerResolver<ServerWebExchange> {

    private final Map<String, ReactiveAuthenticationManager> map;
    private final JwtKidIssuerCache kidIssuerCache;

    public IssuerAuthenticationManagerResolver(Map<String, ReactiveAuthenticationManager> map) {
        this(map, new JwtKidIssuerCache(map.keySet()));
    }

    public IssuerAuthenticationManagerResolver(Map<String, ReactiveAuthenticationManager> map, JwtKidIssuerCache kidIssuerCache) {
        this.map = map;
        this.kidIssuerCache = kidIssuerCache;
    }

    @Override
    public Mono<ReactiveAuthenticationManager> resolve(ServerWebExchange exchange) {
        String authorization = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authorization == null || authorization.length() < 8 || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return Mono.empty();
        }
        String token = authorization.substring(7).trim();
        if (token.isEmpty()) {
            return Mono.empty();
        }

        JWT jwt;
        try {
            jwt = JWTParser.parse(token);
        } catch (ParseException e) {
            return Mono.error(new InvalidBearerTokenException("Invalid JWT token", e));
        }

        // Fast path: look up issuer by kid from the header (signed JWTs only).
        String kid = jwt instanceof SignedJWT signedJWT ? signedJWT.getHeader().getKeyID() : null;
        String issuer = null;
        if (kid != null) {
            issuer = kidIssuerCache.lookupIssuer(kid);
        }

        // Fallback: extract issuer from the claims set.
        if (issuer == null) {
            try {
                issuer = jwt.getJWTClaimsSet().getIssuer();
            } catch (ParseException e) {
                return Mono.error(new InvalidBearerTokenException("Invalid JWT claims", e));
            }
        }

        if (issuer == null) {
            return Mono.error(new InvalidBearerTokenException("Invalid JWT issuer claim"));
        }

        ReactiveAuthenticationManager reactiveAuthenticationManager = map.get(issuer);
        if (reactiveAuthenticationManager == null) {
            return Mono.error(new InvalidBearerTokenException("Invalid JWT issuer claim"));
        }

        return Mono.just(reactiveAuthenticationManager);
    }
}
