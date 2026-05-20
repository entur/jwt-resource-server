package org.entur.jwt.spring.config;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.entur.jwt.spring.JwtKidIssuerCache;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

import java.text.ParseException;
import java.util.Map;

public class IssuerAuthenticationManagerResolver implements AuthenticationManagerResolver<HttpServletRequest> {

    private final Map<String, AuthenticationManager> map;
    private final JwtKidIssuerCache kidIssuerCache;
    private final BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();

    public IssuerAuthenticationManagerResolver(Map<String, AuthenticationManager> map) {
        this(map, new JwtKidIssuerCache(map.keySet()));
    }

    public IssuerAuthenticationManagerResolver(Map<String, AuthenticationManager> map, JwtKidIssuerCache kidIssuerCache) {
        this.map = map;
        this.kidIssuerCache = kidIssuerCache;
    }

    @Override
    public AuthenticationManager resolve(HttpServletRequest request) {
        String token = bearerTokenResolver.resolve(request);
        if (token == null) {
            return null;
        }

        JWT jwt;
        try {
            jwt = JWTParser.parse(token);
        } catch (ParseException e) {
            throw new InvalidBearerTokenException("Invalid JWT token", e);
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
                throw new InvalidBearerTokenException("Invalid JWT claims", e);
            }
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
}
