package org.entur.jwt.spring.config;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.entur.jwt.spring.JwtKidIssuerCache;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.util.Assert;

import java.text.ParseException;

/**
 * An {@link AuthenticationManagerResolver} for {@link HttpServletRequest} that routes each
 * request to the right per-issuer {@link AuthenticationManager} using a two-level strategy:
 *
 * <ol>
 *   <li><strong>Fast path</strong> – reads the {@code kid} header from the JWT (cheap header-only
 *       parse via Nimbus) and looks the issuer up in the provided {@link JwtKidIssuerCache}.
 *       This path is available once all issuers have published their JWK sets and no two issuers
 *       share a {@code kid}.</li>
 *   <li><strong>Fallback</strong> – parses the JWT claims set and extracts the {@code iss} claim
 *       using Nimbus.</li>
 * </ol>
 *
 * <p>This class is modelled after the inner
 * {@code JwtIssuerAuthenticationManagerResolver.ResolvingAuthenticationManager} in Spring
 * Security, and delegates actual issuer-to-manager mapping to a caller-supplied
 * {@link AuthenticationManagerResolver AuthenticationManagerResolver&lt;String&gt;}.
 */
public class JwtKidCachingAuthenticationManagerResolver
        implements AuthenticationManagerResolver<HttpServletRequest> {

    private final ResolvingAuthenticationManager resolvingAuthenticationManager;

    public JwtKidCachingAuthenticationManagerResolver(
            AuthenticationManagerResolver<String> issuerAuthenticationManagerResolver,
            JwtKidIssuerCache kidIssuerCache) {
        this.resolvingAuthenticationManager =
                new ResolvingAuthenticationManager(issuerAuthenticationManagerResolver, kidIssuerCache);
    }

    @Override
    public AuthenticationManager resolve(HttpServletRequest request) {
        return resolvingAuthenticationManager;
    }

    // ---- inner ResolvingAuthenticationManager ----------------------------------

    private static final class ResolvingAuthenticationManager implements AuthenticationManager {

        private final AuthenticationManagerResolver<String> issuerAuthenticationManagerResolver;
        private final JwtKidIssuerCache kidIssuerCache;

        ResolvingAuthenticationManager(
                AuthenticationManagerResolver<String> issuerAuthenticationManagerResolver,
                JwtKidIssuerCache kidIssuerCache) {
            this.issuerAuthenticationManagerResolver = issuerAuthenticationManagerResolver;
            this.kidIssuerCache = kidIssuerCache;
        }

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            Assert.isTrue(authentication instanceof BearerTokenAuthenticationToken,
                    "Authentication must be of type BearerTokenAuthenticationToken");
            BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken) authentication;

            String issuer = resolveIssuer(bearer.getToken());
            if (issuer == null) {
                InvalidBearerTokenException ex = new InvalidBearerTokenException("Invalid issuer");
                ex.setAuthenticationRequest(authentication);
                throw ex;
            }

            AuthenticationManager authenticationManager = issuerAuthenticationManagerResolver.resolve(issuer);
            if (authenticationManager == null) {
                InvalidBearerTokenException ex = new InvalidBearerTokenException("Invalid issuer");
                ex.setAuthenticationRequest(authentication);
                throw ex;
            }

            try {
                return authenticationManager.authenticate(authentication);
            } catch (AuthenticationException e) {
                e.setAuthenticationRequest(authentication);
                throw e;
            }
        }

        private String resolveIssuer(String token) {
            JWT jwt;
            try {
                jwt = JWTParser.parse(token);
            } catch (ParseException e) {
                throw new InvalidBearerTokenException("Invalid JWT token", e);
            }

            // Fast path: kid header → cache lookup (no claims parsing needed).
            if (jwt instanceof SignedJWT signedJWT) {
                String kid = signedJWT.getHeader().getKeyID();
                if (kid != null) {
                    String issuer = kidIssuerCache.lookupIssuer(kid);
                    if (issuer != null) {
                        return issuer;
                    }
                }
            }

            // Fallback: extract issuer from JWT claims.
            try {
                return jwt.getJWTClaimsSet().getIssuer();
            } catch (ParseException e) {
                throw new InvalidBearerTokenException("Invalid JWT claims", e);
            }
        }
    }
}
