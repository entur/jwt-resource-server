package org.entur.jwt.spring.config;

import jakarta.servlet.http.HttpServletRequest;
import org.entur.jwt.spring.JwtKidIssuerCache;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationManagerResolver} for {@link HttpServletRequest} that routes each
 * request to the right per-issuer {@link AuthenticationManager} using a two-step strategy:
 *
 * <ol>
 *   <li><strong>Fast path – kid cache</strong> – the raw base64url header segment (before the
 *       first {@code .}) is looked up in the tier-1 raw-header cache (no parsing), then on a
 *       miss the {@code kid} is extracted via a header-only Nimbus parse (tier-2).  Both tiers
 *       are maintained by the supplied {@link JwtKidIssuerCache}.  On a hit the resolved issuer
 *       is used to look up the per-issuer {@link AuthenticationManager} directly.</li>
 *   <li><strong>Fallback – {@link JwtIssuerAuthenticationManagerResolver}</strong> – on a cache
 *       miss (kid unknown or cache not yet warm) the token is delegated to the standard Spring
 *       Security issuer resolver, which performs a full JWT parse to extract the {@code iss}
 *       claim and then routes to the same per-issuer manager map.</li>
 * </ol>
 */
public class JwtKidCachingAuthenticationManagerResolver
        implements AuthenticationManagerResolver<HttpServletRequest> {

    private final ResolvingAuthenticationManager resolvingAuthenticationManager;

    public JwtKidCachingAuthenticationManagerResolver(
            AuthenticationManagerResolver<String> issuerAuthenticationManagerResolver,
            JwtKidIssuerCache kidIssuerCache) {
        // Pre-resolve the fallback manager once; JwtIssuerAuthenticationManagerResolver.resolve()
        // ignores the request and always returns the same inner AuthenticationManager.
        AuthenticationManager fallbackAuthenticationManager =
                new JwtIssuerAuthenticationManagerResolver(issuerAuthenticationManagerResolver)
                        .resolve(null);
        this.resolvingAuthenticationManager =
                new ResolvingAuthenticationManager(issuerAuthenticationManagerResolver, kidIssuerCache,
                        fallbackAuthenticationManager);
    }

    @Override
    public AuthenticationManager resolve(HttpServletRequest request) {
        return resolvingAuthenticationManager;
    }

    // ---- inner ResolvingAuthenticationManager ----------------------------------

    private static final class ResolvingAuthenticationManager implements AuthenticationManager {

        private final AuthenticationManagerResolver<String> issuerAuthenticationManagerResolver;
        private final JwtKidIssuerCache kidIssuerCache;
        private final AuthenticationManager fallbackAuthenticationManager;

        ResolvingAuthenticationManager(
                AuthenticationManagerResolver<String> issuerAuthenticationManagerResolver,
                JwtKidIssuerCache kidIssuerCache,
                AuthenticationManager fallbackAuthenticationManager) {
            this.issuerAuthenticationManagerResolver = issuerAuthenticationManagerResolver;
            this.kidIssuerCache = kidIssuerCache;
            this.fallbackAuthenticationManager = fallbackAuthenticationManager;
        }

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            Assert.isTrue(authentication instanceof BearerTokenAuthenticationToken,
                    "Authentication must be of type BearerTokenAuthenticationToken");
            BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken) authentication;

            // Fast path: tier 1 (raw header string) + tier 2 (kid extraction).
            String issuer = kidIssuerCache.lookupIssuer(bearer.getToken());
            if (issuer != null) {
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

            // Fallback: delegate to JwtIssuerAuthenticationManagerResolver which performs a
            // full JWT parse to extract the iss claim and routes to the per-issuer manager.
            return fallbackAuthenticationManager.authenticate(authentication);
        }
    }
}
