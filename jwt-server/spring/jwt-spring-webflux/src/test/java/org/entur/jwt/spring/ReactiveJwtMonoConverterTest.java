package org.entur.jwt.spring;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

public class ReactiveJwtMonoConverterTest {

    @Test
    public void shouldRetrieveJwksOutsideNonBlockingRequestThread() throws Exception {
        OctetSequenceKey key = new OctetSequenceKey.Builder(new byte[32]).keyID("test-key").build();
        JWKSet keys = new JWKSet(key);
        AtomicReference<Boolean> nonBlockingKeyRetrieval = new AtomicReference<>();
        JWKSource<SecurityContext> source = (selector, context) -> {
            nonBlockingKeyRetrieval.set(Schedulers.isInNonBlockingThread());
            return selector.select(keys);
        };
        JWSVerificationKeySelector<SecurityContext> selector = new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, source);
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(selector);
        processor.setJWTClaimsSetVerifier((claims, context) -> {
        });
        NimbusReactiveJwtDecoder decoder = new NimbusReactiveJwtDecoder(new ReactiveJwtMonoConverter(processor, selector));
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        JwtTimestampValidator validator = new JwtTimestampValidator(Duration.ZERO);
        validator.setClock(Clock.fixed(now, ZoneOffset.UTC));
        decoder.setJwtValidator(validator);
        JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(decoder);

        SignedJWT token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(key.getKeyID()).build(),
                new JWTClaimsSet.Builder().subject("test-subject").issueTime(Date.from(now.minusSeconds(1))).expirationTime(Date.from(now.plusSeconds(60))).build());
        token.sign(new MACSigner(key));

        Scheduler requestScheduler = Schedulers.newSingle("test-request");
        try {
            var authentication = manager.authenticate(new BearerTokenAuthenticationToken(token.serialize())).subscribeOn(requestScheduler).block(Duration.ofSeconds(10));

            assertThat(authentication.getName()).isEqualTo("test-subject");
            assertThat(authentication.isAuthenticated()).isTrue();
            assertThat(nonBlockingKeyRetrieval.get()).isFalse();
        } finally {
            requestScheduler.dispose();
        }
    }
}
