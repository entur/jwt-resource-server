package org.entur.jwt.spring.config;

import com.nimbusds.jwt.JWTParser;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapperDecider;
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
    protected final JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider;

    public FastIssuerAuthenticationManager(AuthenticationManagerResolver<String> issuerAuthenticationManagerResolver, JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper, JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider) {
        this.issuerAuthenticationManagerResolver = issuerAuthenticationManagerResolver;
        this.jwtHeaderToIssuerMapper = jwtHeaderToIssuerMapper;
        this.jwtHeaderToIssuerMapperDecider = jwtHeaderToIssuerMapperDecider;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isTrue(authentication instanceof BearerTokenAuthenticationToken,
                "Authentication must be of type BearerTokenAuthenticationToken");
        BearerTokenAuthenticationToken token = (BearerTokenAuthenticationToken) authentication;

        String issuer = jwtHeaderToIssuerMapper.get(token.getToken());
        if(issuer != null) {
            // fast path
            AuthenticationManager authenticationManager = issuerAuthenticationManagerResolver.resolve(issuer);

            try {
                return getAuthentication(authentication, authenticationManager);
            } catch (AuthenticationException e) {
                // the header might also be used by another issuer (i.e. which shares signing key and key id),
                // if so authenticate as usual (slow path). Otherwise do not authenticate again, i.e. for an expired token.
                if(!isOtherIssuer(token, issuer)) {
                    throw e;
                }
            }
        }
        // slow path
        issuer = issuerConverter.convert(token);

        AuthenticationManager authenticationManager = issuerAuthenticationManagerResolver.resolve(issuer);

        Authentication result = getAuthentication(authentication, authenticationManager);

        if(result instanceof JwtAuthenticationToken r) {
            if(jwtHeaderToIssuerMapperDecider.apply(r.getToken())) {
                // cache this jwt header to issuer mapping for future requests with the same token
                jwtHeaderToIssuerMapper.add(issuer, token.getToken());
            }
        }

        return result;
    }

    /**
     * @return true if the token's (not yet verified) issuer claim names another issuer than the given issuer
     */
    private boolean isOtherIssuer(BearerTokenAuthenticationToken token, String issuer) {
        try {
            return !issuer.equals(issuerConverter.convert(token));
        } catch (AuthenticationException e) {
            // not a JWT, or no issuer claim
            return false;
        }
    }

    // from JwtIssuerAuthenticationManagerResolver
    private static @NonNull Authentication getAuthentication(Authentication authentication, AuthenticationManager authenticationManager) {
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