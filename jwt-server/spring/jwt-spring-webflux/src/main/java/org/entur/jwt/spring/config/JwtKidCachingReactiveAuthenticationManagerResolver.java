package org.entur.jwt.spring.config;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
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
 * request to the right per-issuer {@link ReactiveAuthenticationManager} using a three-tier strategy:
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
