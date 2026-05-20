package org.entur.jwt.spring.config;

import org.entur.jwt.spring.JwtHeaderKidExtractor;
import org.entur.jwt.spring.JwtIssuerBase64Matcher;
import org.entur.jwt.spring.JwtIssuerClaimExtractor;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

public class IssuerAuthenticationManagerResolver implements ReactiveAuthenticationManagerResolver<ServerWebExchange> {

    private final Map<String, ReactiveAuthenticationManager> map;
    private final Map<String, String> kidToIssuer;
    private final JwtIssuerBase64Matcher matcher;

    public IssuerAuthenticationManagerResolver(Map<String, ReactiveAuthenticationManager> map) {
        this(map, Map.of());
    }

    public IssuerAuthenticationManagerResolver(Map<String, ReactiveAuthenticationManager> map, Map<String, String> kidToIssuer) {
        this.map = map;
        this.kidToIssuer = kidToIssuer;
        this.matcher = new JwtIssuerBase64Matcher(map.keySet());
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

        String issuer = resolveIssuerByKid(token);
        if (issuer == null) {
            issuer = matcher.matchIssuerFromToken(token);
        }
        if (issuer == null) {
            issuer = JwtIssuerClaimExtractor.extractIssuer(token);
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

    private String resolveIssuerByKid(String token) {
        if (kidToIssuer.isEmpty()) {
            return null;
        }
        String keyId = JwtHeaderKidExtractor.extractKid(token);
        if (keyId == null) {
            return null;
        }
        return kidToIssuer.get(keyId);
    }
}
