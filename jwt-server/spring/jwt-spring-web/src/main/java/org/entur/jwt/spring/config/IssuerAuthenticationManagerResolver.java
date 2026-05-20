package org.entur.jwt.spring.config;

import jakarta.servlet.http.HttpServletRequest;
import org.entur.jwt.spring.JwtHeaderKidExtractor;
import org.entur.jwt.spring.JwtIssuerBase64Matcher;
import org.entur.jwt.spring.JwtIssuerClaimExtractor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

import java.util.Map;

public class IssuerAuthenticationManagerResolver implements AuthenticationManagerResolver<HttpServletRequest> {

    private final Map<String, AuthenticationManager> map;
    private final Map<String, String> kidToIssuer;
    private final JwtIssuerBase64Matcher matcher;
    private final BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();

    public IssuerAuthenticationManagerResolver(Map<String, AuthenticationManager> map) {
        this(map, Map.of());
    }

    public IssuerAuthenticationManagerResolver(Map<String, AuthenticationManager> map, Map<String, String> kidToIssuer) {
        this.map = map;
        this.kidToIssuer = kidToIssuer;
        this.matcher = new JwtIssuerBase64Matcher(map.keySet());
    }

    @Override
    public AuthenticationManager resolve(HttpServletRequest request) {
        String token = bearerTokenResolver.resolve(request);
        if (token == null) {
            return null;
        }
        String issuer = resolveIssuerByKid(token);
        if (issuer == null) {
            issuer = matcher.matchIssuerFromToken(token);
        }
        if (issuer == null) {
            issuer = JwtIssuerClaimExtractor.extractIssuer(token);
        }
        if (issuer == null) {
            throw new InvalidBearerTokenException("Invalid JWT issuer claim");
        }
        AuthenticationManager authenticationManager = map.get(issuer);
        if (authenticationManager == null) {
            throw new InvalidBearerTokenException("Invalid JWT issuer claim");
        }
        return authenticationManager;
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
