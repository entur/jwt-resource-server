package org.entur.jwt.spring.config;

import org.entur.jwt.spring.JwtKidIssuerCache;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * A {@link ReactiveAuthenticationManagerResolver} for {@link ServerWebExchange} that routes each
 * request to the right per-issuer {@link ReactiveAuthenticationManager} using a two-step strategy:
 *
 * <ol>
 *   <li><strong>Fast path – kid cache</strong> – the raw base64url header segment (before the
 *       first {@code .}) is looked up in the tier-1 raw-header cache (no parsing), then on a
 *       miss the {@code kid} is extracted via a header-only Nimbus parse (tier-2).  Both tiers
 *       are maintained by the supplied {@link JwtKidIssuerCache}.  On a hit the resolved issuer
 *       is used to look up the per-issuer {@link ReactiveAuthenticationManager} directly.</li>
 *   <li><strong>Fallback – {@link JwtIssuerReactiveAuthenticationManagerResolver}</strong> – on
 *       a cache miss (kid unknown or cache not yet warm) the token is delegated to the standard
 *       Spring Security reactive issuer resolver, which performs a full JWT parse to extract the
 *       {@code iss} claim and then routes to the same per-issuer manager map.</li>
 * </ol>
 */
public class JwtKidCachingReactiveAuthenticationManagerResolver
        implements ReactiveAuthenticationManagerResolver<ServerWebExchange> {

    private final ResolvingAuthenticationManager resolvingAuthenticationManager;

    public JwtKidCachingReactiveAuthenticationManagerResolver(
            ReactiveAuthenticationManagerResolver<String> issuerAuthenticationManagerResolver,
            JwtKidIssuerCache kidIssuerCache) {
        // Pre-resolve the fallback manager once; JwtIssuerReactiveAuthenticationManagerResolver
        // .resolve() ignores the exchange and always returns the same inner manager via Mono.just().
        ReactiveAuthenticationManager fallbackAuthenticationManager =
                new JwtIssuerReactiveAuthenticationManagerResolver(issuerAuthenticationManagerResolver)
                        .resolve(null)
                        .block(); // safe: resolve() returns Mono.just(), no I/O
        this.resolvingAuthenticationManager =
                new ResolvingAuthenticationManager(issuerAuthenticationManagerResolver, kidIssuerCache,
                        fallbackAuthenticationManager);
    }

    @Override
    public Mono<ReactiveAuthenticationManager> resolve(ServerWebExchange exchange) {
        return Mono.just(resolvingAuthenticationManager);
    }

    // ---- inner ResolvingAuthenticationManager ----------------------------------

    private static final class ResolvingAuthenticationManager implements ReactiveAuthenticationManager {

        private final ReactiveAuthenticationManagerResolver<String> issuerAuthenticationManagerResolver;
        private final JwtKidIssuerCache kidIssuerCache;
        private final ReactiveAuthenticationManager fallbackAuthenticationManager;

        ResolvingAuthenticationManager(
                ReactiveAuthenticationManagerResolver<String> issuerAuthenticationManagerResolver,
                JwtKidIssuerCache kidIssuerCache,
                ReactiveAuthenticationManager fallbackAuthenticationManager) {
            this.issuerAuthenticationManagerResolver = issuerAuthenticationManagerResolver;
            this.kidIssuerCache = kidIssuerCache;
            this.fallbackAuthenticationManager = fallbackAuthenticationManager;
        }

        @Override
        public Mono<Authentication> authenticate(Authentication authentication) {
            return Mono.defer(() -> {
                if (!(authentication instanceof BearerTokenAuthenticationToken bearer)) {
                    return Mono.error(new IllegalArgumentException(
                            "Authentication must be of type BearerTokenAuthenticationToken"));
                }

                // Fast path: tier 1 (raw header string) + tier 2 (kid extraction).
                String issuer = kidIssuerCache.lookupIssuer(bearer.getToken());
                if (issuer != null) {
                    return issuerAuthenticationManagerResolver.resolve(issuer)
                            .switchIfEmpty(Mono.defer(() -> {
                                InvalidBearerTokenException ex = new InvalidBearerTokenException("Invalid issuer");
                                ex.setAuthenticationRequest(authentication);
                                return Mono.error(ex);
                            }))
                            .flatMap(manager -> manager.authenticate(authentication));
                }

                // Fallback: delegate to JwtIssuerReactiveAuthenticationManagerResolver which
                // performs a full JWT parse to extract the iss claim and routes to the per-issuer manager.
                return fallbackAuthenticationManager.authenticate(authentication);
            });
        }
    }
}
