package org.entur.jwt.spring;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import reactor.core.Disposable;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReactiveJwtMonoConverterTest {

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    private final OctetSequenceKey key = new OctetSequenceKey.Builder(new byte[32]).keyID("test-key").build();
    private final OctetSequenceKey otherKey = new OctetSequenceKey.Builder(secret(1)).keyID("other-key").build();

    private final RecordingJwkSource source = new RecordingJwkSource(new JWKSet(key));

    private Scheduler requestScheduler;
    private Scheduler jwtScheduler;

    // i.e. like a caching JWK source: blocks while refreshing, and refreshes if no key matches
    private static class RecordingJwkSource implements JWKSource<SecurityContext> {

        private volatile JWKSet keys;
        private volatile JWKSet refreshed;
        private volatile CountDownLatch blocked;
        private volatile KeySourceException failure;
        private volatile Error error;

        private final List<Thread> threads = new CopyOnWriteArrayList<>();
        private final AtomicInteger active = new AtomicInteger();
        private final AtomicInteger maxActive = new AtomicInteger();

        RecordingJwkSource(JWKSet keys) {
            this.keys = keys;
        }

        @Override
        public List<JWK> get(JWKSelector selector, SecurityContext context) throws KeySourceException {
            threads.add(Thread.currentThread());
            maxActive.accumulateAndGet(active.incrementAndGet(), Math::max);
            try {
                CountDownLatch latch = blocked;
                if (latch != null && !latch.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException();
                }
                if (error != null) {
                    throw error;
                }
                if (failure != null) {
                    throw failure;
                }
                List<JWK> selected = selector.select(keys);
                if (selected.isEmpty() && refreshed != null) {
                    keys = refreshed;
                    selected = selector.select(keys);
                }
                return selected;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new KeySourceException("Interrupted", e);
            } finally {
                active.decrementAndGet();
            }
        }
    }

    private static class TimedConverter extends ReactiveJwtMonoConverter {

        private long nanos;

        TimedConverter(DefaultJWTProcessor<SecurityContext> jwtProcessor, JWSVerificationKeySelector<SecurityContext> selector, Scheduler scheduler) {
            super(jwtProcessor, selector, scheduler);
        }

        @Override
        protected long nanoTime() {
            return nanos;
        }

        void advance(long duration, TimeUnit unit) {
            nanos += unit.toNanos(duration);
        }
    }

    @BeforeEach
    void setUp() {
        requestScheduler = Schedulers.newSingle("test-request");
        jwtScheduler = Schedulers.newBoundedElastic(4, 100, "test-jwt");
    }

    @AfterEach
    void tearDown() {
        requestScheduler.dispose();
        jwtScheduler.dispose();
    }

    @Test
    void shouldLookUpKeysOutsideNonBlockingRequestThread() throws Exception {
        JwtReactiveAuthenticationManager manager = manager(new ReactiveJwtMonoConverter(processor(), selector(), jwtScheduler));
        AtomicReference<Thread> authenticationThread = new AtomicReference<>();

        Authentication authentication = authenticate(manager, token(key)).doOnNext(a -> authenticationThread.set(Thread.currentThread())).block(Duration.ofSeconds(10));

        assertThat(authentication.getName()).isEqualTo("test-subject");
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(source.threads).isNotEmpty().allMatch(thread -> thread.getName().startsWith("test-jwt-"));
        // the request continues on a non-blocking thread, not on the JWT processing scheduler
        assertThat(authenticationThread.get().getName()).doesNotStartWith("test-jwt-");
        assertThat(Schedulers.isNonBlockingThread(authenticationThread.get())).isTrue();
    }

    @Test
    void shouldVerifyWithLookedUpKeysOnCallingThread() throws Exception {
        JwtReactiveAuthenticationManager manager = manager(new ReactiveJwtMonoConverter(processor(), selector(), jwtScheduler));
        authenticate(manager, token(key)).block(Duration.ofSeconds(10));
        int lookups = source.threads.size();

        AtomicReference<Thread> authenticationThread = new AtomicReference<>();
        Authentication authentication = authenticate(manager, token(key)).doOnNext(a -> authenticationThread.set(Thread.currentThread())).block(Duration.ofSeconds(10));

        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(source.threads).hasSize(lookups);
        assertThat(authenticationThread.get().getName()).startsWith("test-request");
    }

    @Test
    void shouldLookUpKeysOnceForConcurrentRequests() throws Exception {
        JwtReactiveAuthenticationManager manager = manager(new ReactiveJwtMonoConverter(processor(), selector(), jwtScheduler));
        CountDownLatch latch = new CountDownLatch(1);
        source.blocked = latch;

        List<CompletableFuture<Authentication>> authentications = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            authentications.add(manager.authenticate(new BearerTokenAuthenticationToken(token(key))).toFuture());
        }
        latch.countDown();

        for (CompletableFuture<Authentication> authentication : authentications) {
            assertThat(authentication.get(10, TimeUnit.SECONDS).isAuthenticated()).isTrue();
        }
        // a single lookup, i.e. one in-flight request to the JWK source
        assertThat(source.threads).hasSize(1);
        assertThat(source.maxActive.get()).isEqualTo(1);
    }

    @Test
    void shouldLookUpUnknownKey() throws Exception {
        JwtReactiveAuthenticationManager manager = manager(new ReactiveJwtMonoConverter(processor(), selector(), jwtScheduler));
        authenticate(manager, token(key)).block(Duration.ofSeconds(10));

        // i.e. key rotation
        source.refreshed = new JWKSet(List.of(key, otherKey));

        assertThat(authenticate(manager, token(otherKey)).block(Duration.ofSeconds(10)).isAuthenticated()).isTrue();
    }

    @Test
    void shouldRejectTokenWithUnknownKeyAfterLookup() throws Exception {
        JwtReactiveAuthenticationManager manager = manager(new ReactiveJwtMonoConverter(processor(), selector(), jwtScheduler));
        authenticate(manager, token(key)).block(Duration.ofSeconds(10));
        int lookups = source.threads.size();

        assertThatThrownBy(() -> authenticate(manager, token(otherKey)).block(Duration.ofSeconds(10))).isInstanceOf(InvalidBearerTokenException.class);
        // the keys, the unknown key (so that the JWK source refreshes) and then the keys again, but no further lookups
        assertThat(source.threads).hasSize(lookups + 3);
    }

    @Test
    void shouldLookUpKeysAgainInBackgroundAndAfterExpiry() throws Exception {
        TimedConverter converter = new TimedConverter(processor(), selector(), jwtScheduler);
        JwtReactiveAuthenticationManager manager = manager(converter);
        authenticate(manager, token(key)).block(Duration.ofSeconds(10));
        assertThat(source.threads).hasSize(1);

        // keys are still valid, so verify on the calling thread and look up the keys in the background
        converter.advance(6, TimeUnit.SECONDS);
        AtomicReference<Thread> authenticationThread = new AtomicReference<>();
        authenticate(manager, token(key)).doOnNext(a -> authenticationThread.set(Thread.currentThread())).block(Duration.ofSeconds(10));
        assertThat(authenticationThread.get().getName()).startsWith("test-request");
        awaitLookups(2);

        // the keys looked up in the background have expired, so wait for a lookup
        converter.advance(11, TimeUnit.SECONDS);
        source.failure = new KeySourceException("Unavailable");
        assertThatThrownBy(() -> authenticate(manager, token(key)).block(Duration.ofSeconds(10))).isInstanceOf(AuthenticationServiceException.class);
        assertThat(source.threads).hasSize(3);

        // a failed lookup is not reused
        source.failure = null;
        assertThat(authenticate(manager, token(key)).block(Duration.ofSeconds(10)).isAuthenticated()).isTrue();
        assertThat(source.threads).hasSize(4);
    }

    @Test
    void shouldFailRequestsWaitingForLookupWhenSchedulerRejects() throws Exception {
        CountDownLatch scheduling = new CountDownLatch(1);
        CountDownLatch rejected = new CountDownLatch(1);
        Scheduler rejecting = new Scheduler() {
            @Override
            public Disposable schedule(Runnable task) {
                scheduling.countDown();
                try {
                    rejected.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                throw new RejectedExecutionException("Rejected");
            }

            @Override
            public Worker createWorker() {
                throw new UnsupportedOperationException();
            }
        };
        ReactiveJwtMonoConverter converter = new ReactiveJwtMonoConverter(processor(), selector(), rejecting);
        SignedJWT jwt = SignedJWT.parse(token(key));

        // the first request starts the lookup, and blocks in the scheduler
        CompletableFuture<JWTClaimsSet> first = new CompletableFuture<>();
        Thread thread = new Thread(() -> converter.convert(jwt).subscribe(first::complete, first::completeExceptionally));
        thread.start();
        assertThat(scheduling.await(10, TimeUnit.SECONDS)).isTrue();

        // the second request waits for that lookup
        CompletableFuture<JWTClaimsSet> second = converter.convert(jwt).toFuture();
        rejected.countDown();

        assertThatThrownBy(() -> first.get(5, TimeUnit.SECONDS)).hasCauseInstanceOf(JwtException.class);
        assertThatThrownBy(() -> second.get(5, TimeUnit.SECONDS)).hasCauseInstanceOf(JwtException.class);
        thread.join();
    }

    @Test
    void shouldFailAndRecoverWhenLookupThrowsError() throws Exception {
        JwtReactiveAuthenticationManager manager = manager(new ReactiveJwtMonoConverter(processor(), selector(), jwtScheduler));
        source.error = new AssertionError("Unexpected");

        // do not wait for this lookup forever
        assertThatThrownBy(() -> authenticate(manager, token(key)).block(Duration.ofSeconds(5))).isInstanceOf(AuthenticationServiceException.class);

        source.error = null;
        assertThat(authenticate(manager, token(key)).block(Duration.ofSeconds(5)).isAuthenticated()).isTrue();
    }

    @Test
    void shouldNotModifyJwtProcessor() {
        DefaultJWTProcessor<SecurityContext> processor = processor();
        JWSKeySelector<SecurityContext> original = (header, context) -> List.of();
        processor.setJWSKeySelector(original);

        new ReactiveJwtMonoConverter(processor, selector(), jwtScheduler);

        assertThat(processor.getJWSKeySelector()).isSameAs(original);
    }

    @Test
    void shouldUseClaimsVerifierOfJwtProcessor() {
        DefaultJWTProcessor<SecurityContext> processor = processor();
        processor.setJWTClaimsSetVerifier((claims, context) -> {
            throw new BadJWTException("Rejected");
        });
        JwtReactiveAuthenticationManager manager = manager(new ReactiveJwtMonoConverter(processor, selector(), jwtScheduler));

        assertThatThrownBy(() -> authenticate(manager, token(key)).block(Duration.ofSeconds(10))).isInstanceOf(InvalidBearerTokenException.class);
    }

    @Test
    void shouldUseTypeVerifierOfJwtProcessor() {
        DefaultJWTProcessor<SecurityContext> processor = processor();
        processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt")));
        JwtReactiveAuthenticationManager manager = manager(new ReactiveJwtMonoConverter(processor, selector(), jwtScheduler));

        // the token has no type
        assertThatThrownBy(() -> authenticate(manager, token(key)).block(Duration.ofSeconds(10))).isInstanceOf(InvalidBearerTokenException.class);
    }

    private void awaitLookups(int count) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 10_000;
        while (source.threads.size() < count && System.currentTimeMillis() < deadline) {
            Thread.sleep(10);
        }
        assertThat(source.threads).hasSize(count);
    }

    private JWSVerificationKeySelector<SecurityContext> selector() {
        return new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, source);
    }

    private static DefaultJWTProcessor<SecurityContext> processor() {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWTClaimsSetVerifier((claims, context) -> {
        });
        return processor;
    }

    private static JwtReactiveAuthenticationManager manager(ReactiveJwtMonoConverter converter) {
        NimbusReactiveJwtDecoder decoder = new NimbusReactiveJwtDecoder(converter);
        JwtTimestampValidator validator = new JwtTimestampValidator(Duration.ZERO);
        validator.setClock(Clock.fixed(NOW, ZoneOffset.UTC));
        decoder.setJwtValidator(validator);
        return new JwtReactiveAuthenticationManager(decoder);
    }

    private Mono<Authentication> authenticate(JwtReactiveAuthenticationManager manager, String token) {
        return manager.authenticate(new BearerTokenAuthenticationToken(token)).subscribeOn(requestScheduler);
    }

    private static byte[] secret(int value) {
        byte[] secret = new byte[32];
        Arrays.fill(secret, (byte) value);
        return secret;
    }

    private static String token(OctetSequenceKey key) throws Exception {
        SignedJWT token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(key.getKeyID()).build(),
                new JWTClaimsSet.Builder().subject("test-subject").issueTime(Date.from(NOW.minusSeconds(1))).expirationTime(Date.from(NOW.plusSeconds(60))).build());
        token.sign(new MACSigner(key));
        return token.serialize();
    }
}
