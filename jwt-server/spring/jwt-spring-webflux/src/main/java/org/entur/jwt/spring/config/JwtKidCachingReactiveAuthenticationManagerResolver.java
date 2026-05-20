package org.entur.jwt.spring.config;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.entur.jwt.spring.JwtKidIssuerCache;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.text.ParseException;

/**
 * A {@link ReactiveAuthenticationManagerResolver} for {@link ServerWebExchange} that routes each
 * request to the right per-issuer {@link ReactiveAuthenticationManager} using a two-level strategy:
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
 * {@code JwtIssuerReactiveAuthenticationManagerResolver.ResolvingAuthenticationManager} in Spring
 * Security, and delegates actual issuer-to-manager mapping to a caller-supplied
 * {@link ReactiveAuthenticationManagerResolver ReactiveAuthenticationManagerResolver&lt;String&gt;}.
 */
public class JwtKidCachingReactiveAuthenticationManagerResolver
        implements ReactiveAuthenticationManagerResolver<ServerWebExchange> {

    private final ResolvingAuthenticationManager resolvingAuthenticationManager;

    public JwtKidCachingReactiveAuthenticationManagerResolver(
            ReactiveAuthenticationManagerResolver<String> issuerAuthenticationManagerResolver,
            JwtKidIssuerCache kidIssuerCache) {
        this.resolvingAuthenticationManager =
                new ResolvingAuthenticationManager(issuerAuthenticationManagerResolver, kidIssuerCache);
    }

    @Override
    public Mono<ReactiveAuthenticationManager> resolve(ServerWebExchange exchange) {
        return Mono.just(resolvingAuthenticationManager);
    }

    // ---- inner ResolvingAuthenticationManager ----------------------------------

    private static final class ResolvingAuthenticationManager implements ReactiveAuthenticationManager {

        private final ReactiveAuthenticationManagerResolver<String> issuerAuthenticationManagerResolver;
        private final JwtKidIssuerCache kidIssuerCache;

        ResolvingAuthenticationManager(
                ReactiveAuthenticationManagerResolver<String> issuerAuthenticationManagerResolver,
                JwtKidIssuerCache kidIssuerCache) {
            this.issuerAuthenticationManagerResolver = issuerAuthenticationManagerResolver;
            this.kidIssuerCache = kidIssuerCache;
        }

        @Override
        public Mono<Authentication> authenticate(Authentication authentication) {
            return Mono.defer(() -> {
                if (!(authentication instanceof BearerTokenAuthenticationToken bearer)) {
                    return Mono.error(new IllegalArgumentException(
                            "Authentication must be of type BearerTokenAuthenticationToken"));
                }

                String issuer;
                try {
                    issuer = resolveIssuer(bearer.getToken());
                } catch (InvalidBearerTokenException e) {
                    e.setAuthenticationRequest(authentication);
                    return Mono.error(e);
                }

                if (issuer == null) {
                    InvalidBearerTokenException ex = new InvalidBearerTokenException("Invalid issuer");
                    ex.setAuthenticationRequest(authentication);
                    return Mono.error(ex);
                }

                return issuerAuthenticationManagerResolver.resolve(issuer)
                        .switchIfEmpty(Mono.defer(() -> {
                            InvalidBearerTokenException ex = new InvalidBearerTokenException("Invalid issuer");
                            ex.setAuthenticationRequest(authentication);
                            return Mono.error(ex);
                        }))
                        .flatMap(manager -> manager.authenticate(authentication));
            });
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
