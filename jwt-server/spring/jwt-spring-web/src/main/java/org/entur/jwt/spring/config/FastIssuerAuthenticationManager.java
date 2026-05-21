package org.entur.jwt.spring.config;

import com.nimbusds.jwt.JWTParser;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.Assert;

public class FastIssuerAuthenticationManager implements AuthenticationManager {

    protected final JwtClaimIssuerConverter issuerConverter = new JwtClaimIssuerConverter();
    protected final AuthenticationManagerResolver<String> issuerAuthenticationManagerResolver;
    protected final JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper;

    public FastIssuerAuthenticationManager(AuthenticationManagerResolver<String> issuerAuthenticationManagerResolver, JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper) {
        this.issuerAuthenticationManagerResolver = issuerAuthenticationManagerResolver;
        this.jwtHeaderToIssuerMapper = jwtHeaderToIssuerMapper;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isTrue(authentication instanceof BearerTokenAuthenticationToken,
                "Authentication must be of type BearerTokenAuthenticationToken");
        BearerTokenAuthenticationToken token = (BearerTokenAuthenticationToken) authentication;

        String issuer = jwtHeaderToIssuerMapper.get(token.getToken());
        if(issuer != null) {
            // fast path
            AuthenticationManager authenticationManager = this.issuerAuthenticationManagerResolver.resolve(issuer);

            return getAuthentication(authentication, authenticationManager);
        } else {
            // slow path
            issuer = issuerConverter.convert(token);

            AuthenticationManager authenticationManager = issuerAuthenticationManagerResolver.resolve(issuer);

            Authentication result = getAuthentication(authentication, authenticationManager);

            if(result instanceof JwtAuthenticationToken) {
                // cache this jwt header to issuer mapping for future requests with the same token
                jwtHeaderToIssuerMapper.add(issuer, token.getToken());
            }

            return result;
        }
    }

    // from JwtIssuerAuthenticationManagerResolver
    private static @org.jspecify.annotations.NonNull Authentication getAuthentication(Authentication authentication, AuthenticationManager authenticationManager) {
        if (authenticationManager == null) {
           AuthenticationException ex = new InvalidBearerTokenException("Invalid issuer");
           ex.setAuthenticationRequest(authentication);
           throw ex;
       }
        try {
            return authenticationManager.authenticate(authentication);
        }
        catch (AuthenticationException ex) {
            ex.setAuthenticationRequest(authentication);
            throw ex;
        }
    }

    // from JwtIssuerAuthenticationManagerResolver
    private static class JwtClaimIssuerConverter implements Converter<BearerTokenAuthenticationToken, String> {

        @Override
        public String convert(@NonNull BearerTokenAuthenticationToken authentication) {
            String token = authentication.getToken();
            try {
                String issuer = JWTParser.parse(token).getJWTClaimsSet().getIssuer();
                if (issuer != null) {
                    return issuer;
                }
            }
            catch (Exception cause) {
                AuthenticationException ex = new InvalidBearerTokenException(cause.getMessage(), cause);
                ex.setAuthenticationRequest(authentication);
                throw ex;
            }
            AuthenticationException ex = new InvalidBearerTokenException("Missing issuer");
            ex.setAuthenticationRequest(authentication);
            throw ex;
        }

    }

}