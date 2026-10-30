package org.entur.jwt.spring.config;

import com.nimbusds.jwt.JWTParser;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapperDecider;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

public class FastReactiveIssuerAuthenticationManager implements ReactiveAuthenticationManager {

    protected final JwtClaimIssuerConverter issuerConverter = new JwtClaimIssuerConverter();
    protected final ReactiveIssuerAuthenticationManagerResolver issuerAuthenticationManagerResolver;
    protected final JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper;
    protected final JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider;

    public FastReactiveIssuerAuthenticationManager(ReactiveIssuerAuthenticationManagerResolver issuerAuthenticationManagerResolver, JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper, JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider) {
        this.issuerAuthenticationManagerResolver = issuerAuthenticationManagerResolver;
        this.jwtHeaderToIssuerMapper = jwtHeaderToIssuerMapper;
        this.jwtHeaderToIssuerMapperDecider = jwtHeaderToIssuerMapperDecider;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        Assert.isTrue(authentication instanceof BearerTokenAuthenticationToken,
                "Authentication must be of type BearerTokenAuthenticationToken");
        BearerTokenAuthenticationToken token = (BearerTokenAuthenticationToken) authentication;

        String issuer = jwtHeaderToIssuerMapper.get(token.getToken());
        if (issuer != null) {
            // fast path
            return resolveAndAuthenticate(issuer, authentication)
                    // the header might also be used by another issuer (i.e. which shares signing key and key id),
                    // if so authenticate as usual (slow path). Otherwise do not authenticate again, i.e. for an expired token.
                    .onErrorResume(AuthenticationException.class, e -> isOtherIssuer(token, issuer)
                            .flatMap(otherIssuer -> otherIssuer ? authenticateByIssuerClaim(token) : Mono.error(e)));
        }

        return authenticateByIssuerClaim(token);
    }

    private Mono<Authentication> authenticateByIssuerClaim(BearerTokenAuthenticationToken token) {
        // slow path: parse the JWT to extract the issuer
        // then populate the cache
        return this.issuerConverter.convert(token)
                .flatMap(convertIssuer -> resolveAndAuthenticate(convertIssuer, token)
                        .doOnNext(result -> {
                            if (result instanceof JwtAuthenticationToken t) {
                                if(jwtHeaderToIssuerMapperDecider.apply(t.getToken())) {
                                    // cache this jwt header to issuer mapping for future requests with the same token
                                    jwtHeaderToIssuerMapper.add(convertIssuer, token.getToken());
                                }
                            }
                        }));
    }

    /**
     * @return true if the token's (not yet verified) issuer claim names another issuer than the given issuer
     */
    private Mono<Boolean> isOtherIssuer(BearerTokenAuthenticationToken token, String issuer) {
        return this.issuerConverter.convert(token)
                .map(tokenIssuer -> !tokenIssuer.equals(issuer))
                // not a JWT, or no issuer claim
                .onErrorReturn(AuthenticationException.class, false);
    }

    private Mono<Authentication> resolveAndAuthenticate(String issuer, Authentication authentication) {
        return issuerAuthenticationManagerResolver.resolve(issuer)
                .switchIfEmpty(Mono.defer(() -> {
                    AuthenticationException ex = new InvalidBearerTokenException("Invalid issuer");
                    ex.setAuthenticationRequest(authentication);
                    return Mono.error(ex);
                }))
                .flatMap(manager -> manager.authenticate(authentication)
                .onErrorMap(AuthenticationException.class, ex -> {
                    ex.setAuthenticationRequest(authentication);
                    return ex;
                }));
    }

    // from JwtIssuerAuthenticationManagerResolver
    private static class JwtClaimIssuerConverter implements Converter<BearerTokenAuthenticationToken, Mono<String>> {

        @Override
        public Mono<String> convert(@NonNull BearerTokenAuthenticationToken token) {
            try {
                String issuer = JWTParser.parse(token.getToken()).getJWTClaimsSet().getIssuer();
                if (issuer == null) {
                    AuthenticationException ex = new InvalidBearerTokenException("Missing issuer");
                    ex.setAuthenticationRequest(token);
                    throw ex;
                }
                return Mono.just(issuer);
            } catch (Exception cause) {
                return Mono.error(() -> {
                    AuthenticationException ex = new InvalidBearerTokenException(cause.getMessage(), cause);
                    ex.setAuthenticationRequest(token);
                    return ex;
                });
            }
        }

    }


}