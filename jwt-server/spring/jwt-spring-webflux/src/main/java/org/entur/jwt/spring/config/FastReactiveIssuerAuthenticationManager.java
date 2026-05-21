package org.entur.jwt.spring.config;

import com.nimbusds.jwt.JWTParser;
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
    protected final IssuerAuthenticationManagerResolver issuerAuthenticationManagerResolver;
    protected final JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper;

    public FastReactiveIssuerAuthenticationManager(IssuerAuthenticationManagerResolver issuerAuthenticationManagerResolver, JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper) {
        this.issuerAuthenticationManagerResolver = issuerAuthenticationManagerResolver;
        this.jwtHeaderToIssuerMapper = jwtHeaderToIssuerMapper;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        Assert.isTrue(authentication instanceof BearerTokenAuthenticationToken,
                "Authentication must be of type BearerTokenAuthenticationToken");
        BearerTokenAuthenticationToken token = (BearerTokenAuthenticationToken) authentication;

        String issuer = jwtHeaderToIssuerMapper.get(token.getToken());
        if (issuer != null) {
            // fast path
            return resolveAndAuthenticate(issuer, authentication);
        }

        // slow path: parse the JWT to extract the issuer
        // then populate the cache
        return this.issuerConverter.convert(token)
                .flatMap(convertIssuer -> resolveAndAuthenticate(convertIssuer, authentication))
                .doOnNext(result -> {
                    if (result instanceof JwtAuthenticationToken t) {
                        // cache this jwt header to issuer mapping for future requests with the same token
                        jwtHeaderToIssuerMapper.add(t.getToken().getClaim("iss"), token.getToken());
                    }
                });
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