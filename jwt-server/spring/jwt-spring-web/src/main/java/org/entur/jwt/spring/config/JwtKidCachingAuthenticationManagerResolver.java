package org.entur.jwt.spring.config;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
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
 * request to the right per-issuer {@link AuthenticationManager} using a three-tier strategy:
 *
 * <ol>
 *   <li><strong>Tier 1 – raw header string</strong> – the raw base64url header segment (before
 *       the first {@code .}) is looked up directly in a lazy per-request cache with no parsing
 *       at all.</li>
 *   <li><strong>Tier 2 – kid header</strong> – on a tier-1 miss the header segment is decoded
 *       and the {@code kid} value is extracted (header-only Nimbus parse).  If the kid resolves
 *       to an issuer the result is promoted into the tier-1 cache for next time.</li>
 *   <li><strong>Tier 3 – iss claim</strong> – on a tier-2 miss the full JWT is parsed and the
 *       {@code iss} claim is extracted.</li>
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
            // Tier 1 + 2: extract the raw base64url header segment (before the first '.')
            // and look it up in the header cache – avoids calling JWTParser.parse() when
            // the header is already known.
            int firstDot = token.indexOf('.');
            if (firstDot > 0) {
                String rawHeader = token.substring(0, firstDot);
                String issuer = kidIssuerCache.lookupIssuerByRawHeader(rawHeader);
                if (issuer != null) {
                    return issuer;
                }
            }

            // Fallback: full JWT parse to extract the iss claim.
            JWT jwt;
            try {
                jwt = JWTParser.parse(token);
            } catch (ParseException e) {
                throw new InvalidBearerTokenException("Invalid JWT token", e);
            }
            try {
                return jwt.getJWTClaimsSet().getIssuer();
            } catch (ParseException e) {
                throw new InvalidBearerTokenException("Invalid JWT claims", e);
            }
        }
    }
}
