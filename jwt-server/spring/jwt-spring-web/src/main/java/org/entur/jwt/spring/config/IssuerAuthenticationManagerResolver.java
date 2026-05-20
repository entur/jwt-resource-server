package org.entur.jwt.spring.config;

import jakarta.servlet.http.HttpServletRequest;
import org.entur.jwt.spring.JwtIssuerClaimExtractor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

import java.util.Map;

public class IssuerAuthenticationManagerResolver implements AuthenticationManagerResolver<HttpServletRequest> {

    private final Map<String, AuthenticationManager> map;
    private final BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();

    public IssuerAuthenticationManagerResolver(Map<String, AuthenticationManager> map) {
        this.map = map;
    }

    @Override
    public AuthenticationManager resolve(HttpServletRequest request) {
        String token = bearerTokenResolver.resolve(request);
        if (token == null) {
            return null;
        }
        String issuer = JwtIssuerClaimExtractor.extractIssuer(token);
        if (issuer == null) {
            throw new InvalidBearerTokenException("Invalid JWT issuer claim");
        }
        AuthenticationManager authenticationManager = map.get(issuer);
        if (authenticationManager == null) {
            throw new InvalidBearerTokenException("Invalid JWT issuer claim");
        }
        return authenticationManager;
    }
}
