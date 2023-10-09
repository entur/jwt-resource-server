package org.entur.jwt.spring;

import com.nimbusds.jose.Header;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtException;
import reactor.core.publisher.Mono;

public class ReactiveJwtMonoConverter implements Converter<JWT, Mono<JWTClaimsSet>> {

    private final DefaultJWTProcessor<SecurityContext> jwtProcessor;
    private final JWSVerificationKeySelector selector;

    public ReactiveJwtMonoConverter(DefaultJWTProcessor<SecurityContext> jwtProcessor, JWSVerificationKeySelector selector) {
        this.jwtProcessor = jwtProcessor;
        this.selector = selector;
    }

    @Override
    public Mono<JWTClaimsSet> convert(JWT source) {
        Header header = source.getHeader();
        JWSHeader jwsHeader = (JWSHeader) header;
        if (!selector.isAllowed(jwsHeader.getAlgorithm())) {
            throw new BadJwtException("Unsupported algorithm of " + header.getAlgorithm());
        }

        return Mono.fromCallable(() -> {
            return createClaimsSet(source, null);
        });
    }

    private <C extends SecurityContext> JWTClaimsSet createClaimsSet(JWT parsedToken, C context) {
        try {
            return jwtProcessor.process(parsedToken, context);
        } catch (BadJOSEException ex) {
            throw new BadJwtException("Failed to validate the token", ex);
        } catch (JOSEException ex) {
            throw new JwtException("Failed to validate the token", ex);
        }
    }

    private JWKSelector createSelector(JWSVerificationKeySelector verificationKeySelector, Header header) {
        JWSHeader jwsHeader = (JWSHeader) header;
        if (!verificationKeySelector.isAllowed(jwsHeader.getAlgorithm())) {
            throw new BadJwtException("Unsupported algorithm of " + header.getAlgorithm());
        }
        return new JWKSelector(JWKMatcher.forJWSHeader(jwsHeader));
    }


}
