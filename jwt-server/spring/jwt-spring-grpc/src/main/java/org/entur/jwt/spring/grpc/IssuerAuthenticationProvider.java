package org.entur.jwt.spring.grpc;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;

import java.text.ParseException;
import java.util.Map;

public class IssuerAuthenticationProvider implements AuthenticationProvider {

    private static final String DECODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to decode the Jwt: %s";

    private static Logger LOGGER = LoggerFactory.getLogger(AuthenticationProvider.class);

    private final Map<String, AuthenticationProvider> map;

    public IssuerAuthenticationProvider(Map<String, AuthenticationProvider> map) {
        this.map = map;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        BearerTokenAuthenticationToken bearerTokenAuthenticationToken = (BearerTokenAuthenticationToken) authentication;

        // note to self: there is two jwt classes, Jwt and JWT
        try {
            JWT parse = JWTParser.parse(bearerTokenAuthenticationToken.getToken());

            AuthenticationProvider authenticationProvider = map.get(parse.getJWTClaimsSet().getIssuer());
            if (authenticationProvider != null) {
                return authenticationProvider.authenticate(bearerTokenAuthenticationToken);
            }

            throw new BadCredentialsException("");
        } catch (ParseException ex) {
            throw new BadJwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        LOGGER.info("Supports " + authentication);

        return authentication.equals(org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken.class);
    }
}
