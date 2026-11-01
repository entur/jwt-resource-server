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
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSetBasedJWKSource;
import com.nimbusds.jose.jwk.source.JWKSetCacheRefreshEvaluator;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.jwk.source.RateLimitReachedException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
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

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentLinkedQueue;
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
    private final OctetSequenceKey thirdKey = new OctetSequenceKey.Builder(secret(2)).keyID("third-key").build();

    private final RecordingJwkSource source = new RecordingJwkSource(new JWKSet(key));

    private Scheduler requestScheduler;
    private CountingScheduler jwtScheduler;

    // i.e. like a caching JWK source: blocks while refreshing, and refreshes if no key matches
    private static class RecordingJwkSource extends JWKSetBasedJWKSource<SecurityContext> {

        private volatile JWKSet keys;
        private volatile JWKSet refreshed;
        // the results of the next refreshes, before refreshed
        private final Queue<JWKSet> refreshes = new ConcurrentLinkedQueue<>();
        private volatile CountDownLatch blocked;
        private volatile KeySourceException failure;
        private volatile Error error;
        private volatile KeySourceException refreshFailure;
        private volatile CountDownLatch refreshing;
        private volatile CountDownLatch refreshBlocked;

        private final List<Thread> threads = new CopyOnWriteArrayList<>();
        private final AtomicInteger active = new AtomicInteger();
        private final AtomicInteger maxActive = new AtomicInteger();

        RecordingJwkSource(JWKSet keys) {
            // recognized as a source with a cache by the converter
            super(new CachingJWKSetSource<>(new UnusedJwkSetSource(), 3_600_000, 15_000, null));
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
                if (selected.isEmpty()) {
                    // i.e. refresh, as no key matches
                    CountDownLatch entered = refreshing;
                    if (entered != null) {
                        entered.countDown();
                    }
                    CountDownLatch refreshLatch = refreshBlocked;
                    if (refreshLatch != null && !refreshLatch.await(10, TimeUnit.SECONDS)) {
                        throw new IllegalStateException();
                    }
                    if (refreshFailure != null) {
                        throw refreshFailure;
                    }
                    JWKSet next = refreshes.poll();
                    if (next == null) {
                        next = refreshed;
                    }
                    if (next != null) {
                        keys = next;
                        selected = selector.select(keys);
                    }
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

    private static class UnusedJwkSetSource implements JWKSetSource<SecurityContext> {

        @Override
        public JWKSet getJWKSet(JWKSetCacheRefreshEvaluator refreshEvaluator, long currentTime, SecurityContext context) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void close() {
        }
    }

    // counts the lookups which have finished, i.e. also published their result
    private static class CountingScheduler implements Scheduler {

        private final Scheduler delegate;
        private final AtomicInteger finished = new AtomicInteger();

        CountingScheduler(Scheduler delegate) {
            this.delegate = delegate;
        }

        @Override
        public Disposable schedule(Runnable task) {
            return delegate.schedule(() -> {
                try {
                    task.run();
                } finally {
                    finished.incrementAndGet();
                }
            });
        }

        @Override
        public Worker createWorker() {
            return delegate.createWorker();
        }

        @Override
        public void dispose() {
            delegate.dispose();
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
        jwtScheduler = new CountingScheduler(Schedulers.newBoundedElastic(4, 100, "test-jwt"));
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
        // the keys, the unknown key (so that the JWK source refreshes) and the keys again, but no further lookups
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
        awaitFinishedLookups(2);
        assertThat(source.threads).hasSize(2);

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
        JWSVerificationKeySelector<SecurityContext> selector = selector();
        processor.setJWSKeySelector(selector);

        new ReactiveJwtMonoConverter(processor, selector, jwtScheduler);

        assertThat(processor.getJWSKeySelector()).isSameAs(selector);
    }

    @Test
    void shouldRejectCustomKeySelectorOfJwtProcessor() {
        DefaultJWTProcessor<SecurityContext> processor = processor();
        JWSKeySelector<SecurityContext> custom = (header, context) -> List.of();
        processor.setJWSKeySelector(custom);
        JWSVerificationKeySelector<SecurityContext> selector = selector();

        assertThatThrownBy(() -> new ReactiveJwtMonoConverter(processor, selector, jwtScheduler)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldRejectCustomKeySelector() {
        // i.e. which might not select all keys of the JWK source
        JWSVerificationKeySelector<SecurityContext> custom = new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, source) {
        };

        assertThatThrownBy(() -> new ReactiveJwtMonoConverter(processor(), custom, jwtScheduler)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldCallVerifiersWithoutSecurityContext() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        AtomicInteger contexts = new AtomicInteger();
        DefaultJWTProcessor<SecurityContext> processor = processor();
        processor.setJWSTypeVerifier((type, context) -> {
            calls.incrementAndGet();
            if (context != null) {
                contexts.incrementAndGet();
            }
        });
        processor.setJWTClaimsSetVerifier((claims, context) -> {
            calls.incrementAndGet();
            if (context != null) {
                contexts.incrementAndGet();
            }
        });
        JwtReactiveAuthenticationManager manager = manager(new ReactiveJwtMonoConverter(processor, selector(), jwtScheduler));

        assertThat(authenticate(manager, token(key)).block(Duration.ofSeconds(10)).isAuthenticated()).isTrue();

        assertThat(calls.get()).isEqualTo(2);
        assertThat(contexts.get()).isZero();
    }

    @Test
    void shouldFailWhenRefreshOfUnknownKeyFails() throws Exception {
        JwtReactiveAuthenticationManager manager = manager(new ReactiveJwtMonoConverter(processor(), selector(), jwtScheduler));
        source.refreshFailure = new KeySourceException("Unavailable");

        // not hidden as an invalid token
        assertThatThrownBy(() -> authenticate(manager, token(otherKey)).block(Duration.ofSeconds(10))).isInstanceOf(AuthenticationServiceException.class);
    }

    @Test
    void shouldUseKeysAtHandWhenRefreshIsRateLimited() throws Exception {
        JwtReactiveAuthenticationManager manager = manager(new ReactiveJwtMonoConverter(processor(), selector(), jwtScheduler));
        source.refreshFailure = new RateLimitReachedException();

        assertThat(authenticate(manager, token(key)).block(Duration.ofSeconds(10)).isAuthenticated()).isTrue();
        assertThatThrownBy(() -> authenticate(manager, token(otherKey)).block(Duration.ofSeconds(10))).isInstanceOf(InvalidBearerTokenException.class);
    }

    @Test
    void shouldNotWaitForRefreshOfUnknownKeyWhenKeyIsKnown() throws Exception {
        TimedConverter converter = new TimedConverter(processor(), selector(), jwtScheduler);
        JwtReactiveAuthenticationManager manager = manager(converter);
        authenticate(manager, token(key)).block(Duration.ofSeconds(10));
        converter.advance(11, TimeUnit.SECONDS);

        CountDownLatch refreshing = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        source.refreshed = new JWKSet(List.of(key, otherKey));
        source.refreshing = refreshing;
        source.refreshBlocked = release;
        try {
            // the keys have expired, so this looks up the keys, and then blocks while refreshing for the unknown key
            CompletableFuture<Authentication> unknown = authenticate(manager, token(otherKey)).toFuture();
            assertThat(refreshing.await(10, TimeUnit.SECONDS)).isTrue();

            // the keys which were just looked up are used for known keys
            assertThat(authenticate(manager, token(key)).block(Duration.ofSeconds(5)).isAuthenticated()).isTrue();

            release.countDown();
            assertThat(unknown.get(10, TimeUnit.SECONDS).isAuthenticated()).isTrue();
        } finally {
            release.countDown();
        }
    }

    private static final String JWKS_URL = "https://issuer.example/jwks.json";

    // i.e. like the JWK source of the starter, with or without a cache
    private JWKSource<SecurityContext> urlJwkSource(AtomicInteger fetches, AtomicReference<JWKSet> keys, boolean cache) throws Exception {
        ResourceRetriever retriever = url -> {
            fetches.incrementAndGet();
            return new Resource(keys.get().toString(false), "application/json");
        };
        JWKSourceBuilder<SecurityContext> builder = JWKSourceBuilder.<SecurityContext>create(URI.create(JWKS_URL).toURL(), retriever)
                .rateLimited(false).retrying(false).outageTolerant(false).refreshAheadCache(false);
        // a time to live which is shorter than that of the converter
        return (cache ? builder.cache(2000, 1000) : builder.cache(false)).build();
    }

    @Test
    void shouldNotReuseKeysOfJwkSourceWithoutCache() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        AtomicReference<JWKSet> keys = new AtomicReference<>(new JWKSet(key));
        JWSVerificationKeySelector<SecurityContext> selector = new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, urlJwkSource(fetches, keys, false));
        JwtReactiveAuthenticationManager manager = manager(new ReactiveJwtMonoConverter(processor(), selector, jwtScheduler));

        authenticate(manager, token(key)).block(Duration.ofSeconds(10));
        authenticate(manager, token(key)).block(Duration.ofSeconds(10));

        // the keys of a lookup are only shared by concurrent requests, so that removed keys are not used
        assertThat(fetches.get()).isEqualTo(2);

        // i.e. key rotation, with one fetch for the unknown key
        keys.set(new JWKSet(List.of(key, otherKey)));
        assertThat(authenticate(manager, token(otherKey)).block(Duration.ofSeconds(10)).isAuthenticated()).isTrue();
        assertThat(fetches.get()).isEqualTo(3);
    }

    @Test
    void shouldNotReuseKeysLongerThanCacheOfJwkSource() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        AtomicReference<JWKSet> keys = new AtomicReference<>(new JWKSet(key));
        JWSVerificationKeySelector<SecurityContext> selector = new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, urlJwkSource(fetches, keys, true));
        TimedConverter converter = new TimedConverter(processor(), selector, jwtScheduler);
        JwtReactiveAuthenticationManager manager = manager(converter);
        authenticate(manager, token(key)).block(Duration.ofSeconds(10));
        awaitFinishedLookups(1);

        // within the time to live of the cache, verify on the calling thread (the converter lasts for 10 seconds)
        AtomicReference<Thread> authenticationThread = new AtomicReference<>();
        authenticate(manager, token(key)).doOnNext(a -> authenticationThread.set(Thread.currentThread())).block(Duration.ofSeconds(10));
        assertThat(authenticationThread.get().getName()).startsWith("test-request");

        // after the time to live of the cache, look up the keys
        converter.advance(3, TimeUnit.SECONDS);
        authenticate(manager, token(key)).doOnNext(a -> authenticationThread.set(Thread.currentThread())).block(Duration.ofSeconds(10));
        assertThat(authenticationThread.get().getName()).doesNotStartWith("test-request");
        awaitFinishedLookups(2);
    }

    @Test
    void shouldRejectSubclassOfJwtProcessor() {
        // i.e. which might override the processing of the token
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>() {
        };

        assertThatThrownBy(() -> new ReactiveJwtMonoConverter(processor, selector(), jwtScheduler)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldNotUseRemovedKeysAfterRefresh() throws Exception {
        JwtReactiveAuthenticationManager manager = manager(new ReactiveJwtMonoConverter(processor(), selector(), jwtScheduler));
        authenticate(manager, token(key)).block(Duration.ofSeconds(10));

        // i.e. key rotation, which removes the key
        source.refreshed = new JWKSet(otherKey);

        assertThat(authenticate(manager, token(otherKey)).block(Duration.ofSeconds(10)).isAuthenticated()).isTrue();
        assertThatThrownBy(() -> authenticate(manager, token(key)).block(Duration.ofSeconds(10))).isInstanceOf(InvalidBearerTokenException.class);
    }

    @Test
    void shouldNotReuseKeysOfUnknownJwkSourceButRefreshUnknownKeys() throws Exception {
        // i.e. a wrapper, which might wrap a source without cache
        JWKSource<SecurityContext> wrapper = (selector, context) -> source.get(selector, context);
        JWSVerificationKeySelector<SecurityContext> selector = new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, wrapper);
        JwtReactiveAuthenticationManager manager = manager(new ReactiveJwtMonoConverter(processor(), selector, jwtScheduler));

        authenticate(manager, token(key)).block(Duration.ofSeconds(10));
        authenticate(manager, token(key)).block(Duration.ofSeconds(10));
        assertThat(source.threads).hasSize(2);

        // i.e. key rotation
        source.refreshed = new JWKSet(List.of(key, otherKey));
        assertThat(authenticate(manager, token(otherKey)).block(Duration.ofSeconds(10)).isAuthenticated()).isTrue();
    }

    @Test
    void shouldUseRefreshedKeyOfUnknownJwkSourceWithoutReadingAllKeysAgain() throws Exception {
        AtomicInteger reads = new AtomicInteger();
        // i.e. a wrapper which fails (or reaches a stale replica) for the read after the refresh
        JWKSource<SecurityContext> wrapper = (selector, context) -> {
            if (reads.incrementAndGet() == 4) {
                throw new KeySourceException("Unavailable");
            }
            return source.get(selector, context);
        };
        JWSVerificationKeySelector<SecurityContext> selector = new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, wrapper);
        JwtReactiveAuthenticationManager manager = manager(new ReactiveJwtMonoConverter(processor(), selector, jwtScheduler));
        authenticate(manager, token(key)).block(Duration.ofSeconds(10));

        source.refreshed = new JWKSet(List.of(key, otherKey));
        assertThat(authenticate(manager, token(otherKey)).block(Duration.ofSeconds(10)).isAuthenticated()).isTrue();
        // the keys and the unknown key, which refreshes
        assertThat(reads.get()).isEqualTo(3);
    }

    @Test
    void shouldNotWaitForRefreshOfUnknownKeyWhenKeyIsKnownAndKeysAreNotReused() throws Exception {
        // i.e. a wrapper, so the keys are not reused after the lookup
        JWKSource<SecurityContext> wrapper = (selector, context) -> source.get(selector, context);
        JWSVerificationKeySelector<SecurityContext> selector = new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, wrapper);
        ReactiveJwtMonoConverter converter = new ReactiveJwtMonoConverter(processor(), selector, jwtScheduler);

        CountDownLatch refreshing = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        source.refreshed = new JWKSet(List.of(key, otherKey));
        source.refreshing = refreshing;
        source.refreshBlocked = release;
        try {
            CompletableFuture<JWTClaimsSet> unknown = converter.convert(SignedJWT.parse(token(otherKey))).toFuture();
            assertThat(refreshing.await(10, TimeUnit.SECONDS)).isTrue();

            // the keys of the lookup in progress are used, without waiting for the refresh
            assertThat(converter.convert(SignedJWT.parse(token(key))).toFuture().get(5, TimeUnit.SECONDS).getSubject()).isEqualTo("test-subject");
            assertThat(unknown).isNotDone();

            release.countDown();
            assertThat(unknown.get(10, TimeUnit.SECONDS).getSubject()).isEqualTo("test-subject");
        } finally {
            release.countDown();
        }

        // but not after the lookup
        int reads = source.threads.size();
        converter.convert(SignedJWT.parse(token(key))).block(Duration.ofSeconds(10));
        assertThat(source.threads).hasSize(reads + 1);
    }

    @Test
    void shouldNotWaitForRefreshOfUnknownKeyWhenKeyIsKnownAndRequestWaitsForLookup() throws Exception {
        TimedConverter converter = new TimedConverter(processor(), selector(), jwtScheduler);
        converter.convert(SignedJWT.parse(token(key))).block(Duration.ofSeconds(10));
        converter.advance(11, TimeUnit.SECONDS);

        CountDownLatch lookup = new CountDownLatch(1);
        CountDownLatch refreshing = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        source.blocked = lookup;
        source.refreshed = new JWKSet(List.of(key, otherKey));
        source.refreshing = refreshing;
        source.refreshBlocked = release;
        try {
            // starts a lookup, and a request for a known key waits for it
            CompletableFuture<JWTClaimsSet> unknown = converter.convert(SignedJWT.parse(token(otherKey))).toFuture();
            CompletableFuture<JWTClaimsSet> known = converter.convert(SignedJWT.parse(token(key))).toFuture();
            lookup.countDown();
            assertThat(refreshing.await(10, TimeUnit.SECONDS)).isTrue();

            // the keys have been looked up, but the refresh for the unknown key has not finished
            assertThat(known.get(5, TimeUnit.SECONDS).getSubject()).isEqualTo("test-subject");
            assertThat(unknown).isNotDone();

            release.countDown();
            assertThat(unknown.get(10, TimeUnit.SECONDS).getSubject()).isEqualTo("test-subject");
        } finally {
            release.countDown();
        }
    }

    @Test
    void shouldNotShareKeysOfLookupInProgressForLongerThanKeysAreUsed() throws Exception {
        // i.e. a wrapper, so the keys are not reused after the lookup
        JWKSource<SecurityContext> wrapper = (selector, context) -> source.get(selector, context);
        JWSVerificationKeySelector<SecurityContext> selector = new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, wrapper);
        TimedConverter converter = new TimedConverter(processor(), selector, jwtScheduler);

        CountDownLatch refreshing = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        source.refreshed = new JWKSet(List.of(key, otherKey));
        source.refreshing = refreshing;
        source.refreshBlocked = release;
        try {
            CompletableFuture<JWTClaimsSet> unknown = converter.convert(SignedJWT.parse(token(otherKey))).toFuture();
            assertThat(refreshing.await(10, TimeUnit.SECONDS)).isTrue();

            // the refresh stalls, so the keys at hand are too old to be shared
            converter.advance(11, TimeUnit.SECONDS);
            CompletableFuture<JWTClaimsSet> known = converter.convert(SignedJWT.parse(token(key))).toFuture();
            assertThat(known).isNotDone();

            release.countDown();
            assertThat(known.get(10, TimeUnit.SECONDS).getSubject()).isEqualTo("test-subject");
            assertThat(unknown.get(10, TimeUnit.SECONDS).getSubject()).isEqualTo("test-subject");
        } finally {
            release.countDown();
        }
    }

    @Test
    void shouldNotUseKeysRemovedByRefreshForRequestsWhichWaitedForStalledRefresh() throws Exception {
        // i.e. a wrapper, so the keys are not reused after the lookup
        JWKSource<SecurityContext> wrapper = (selector, context) -> source.get(selector, context);
        JWSVerificationKeySelector<SecurityContext> selector = new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, wrapper);
        TimedConverter converter = new TimedConverter(processor(), selector, jwtScheduler);

        CountDownLatch refreshing = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        // i.e. key rotation, which removes the key
        source.refreshed = new JWKSet(otherKey);
        source.refreshing = refreshing;
        source.refreshBlocked = release;
        try {
            CompletableFuture<JWTClaimsSet> unknown = converter.convert(SignedJWT.parse(token(otherKey))).toFuture();
            assertThat(refreshing.await(10, TimeUnit.SECONDS)).isTrue();

            // the refresh stalls, so the request waits for it
            converter.advance(11, TimeUnit.SECONDS);
            CompletableFuture<JWTClaimsSet> removed = converter.convert(SignedJWT.parse(token(key))).toFuture();
            assertThat(removed).isNotDone();

            release.countDown();
            assertThat(unknown.get(10, TimeUnit.SECONDS).getSubject()).isEqualTo("test-subject");
            // the keys at hand are not replaced by the refresh, so the removed key must not be used
            assertThatThrownBy(() -> removed.get(10, TimeUnit.SECONDS)).hasCauseInstanceOf(JwtException.class);
        } finally {
            release.countDown();
        }
    }

    @Test
    void shouldShareLookupOfJwkSourceWithoutCacheBetweenRequestsForDifferentUnknownKeys() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        CountDownLatch fetching = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ResourceRetriever retriever = url -> {
            fetches.incrementAndGet();
            fetching.countDown();
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return new Resource(new JWKSet(key).toString(false), "application/json");
        };
        JWKSource<SecurityContext> jwkSource = JWKSourceBuilder.<SecurityContext>create(URI.create(JWKS_URL).toURL(), retriever)
                .rateLimited(false).retrying(false).outageTolerant(false).refreshAheadCache(false).cache(false).build();
        JWSVerificationKeySelector<SecurityContext> selector = new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, jwkSource);
        ReactiveJwtMonoConverter converter = new ReactiveJwtMonoConverter(processor(), selector, jwtScheduler);

        try {
            CompletableFuture<JWTClaimsSet> first = converter.convert(SignedJWT.parse(token(key))).toFuture();
            assertThat(fetching.await(10, TimeUnit.SECONDS)).isTrue();
            // the keys were fetched on every call, so the result is conclusive also for requests which wait for it
            CompletableFuture<JWTClaimsSet> second = converter.convert(SignedJWT.parse(token(otherKey))).toFuture();
            CompletableFuture<JWTClaimsSet> third = converter.convert(SignedJWT.parse(token(thirdKey))).toFuture();
            release.countDown();

            assertThat(first.get(10, TimeUnit.SECONDS).getSubject()).isEqualTo("test-subject");
            assertThatThrownBy(() -> second.get(10, TimeUnit.SECONDS)).hasCauseInstanceOf(JwtException.class);
            assertThatThrownBy(() -> third.get(10, TimeUnit.SECONDS)).hasCauseInstanceOf(JwtException.class);
            assertThat(fetches.get()).isEqualTo(1);
        } finally {
            release.countDown();
        }
    }

    @Test
    void shouldLookUpAgainWhenLookupForAnotherTokenIsJoined() throws Exception {
        TimedConverter converter = new TimedConverter(processor(), selector(), jwtScheduler);
        converter.convert(SignedJWT.parse(token(key))).block(Duration.ofSeconds(10));
        converter.advance(11, TimeUnit.SECONDS);

        CountDownLatch lookup = new CountDownLatch(1);
        source.blocked = lookup;
        // i.e. two key rotations
        source.refreshes.add(new JWKSet(List.of(key, otherKey)));
        source.refreshes.add(new JWKSet(List.of(key, otherKey, thirdKey)));

        // all wait for the same lookup. The refresh for the second token is joined by the third token, but does not contain its key
        CompletableFuture<JWTClaimsSet> first = converter.convert(SignedJWT.parse(token(key))).toFuture();
        CompletableFuture<JWTClaimsSet> second = converter.convert(SignedJWT.parse(token(otherKey))).toFuture();
        CompletableFuture<JWTClaimsSet> third = converter.convert(SignedJWT.parse(token(thirdKey))).toFuture();
        lookup.countDown();

        assertThat(first.get(10, TimeUnit.SECONDS).getSubject()).isEqualTo("test-subject");
        assertThat(second.get(10, TimeUnit.SECONDS).getSubject()).isEqualTo("test-subject");
        assertThat(third.get(10, TimeUnit.SECONDS).getSubject()).isEqualTo("test-subject");
    }

    @Test
    void shouldLookUpOnceWhenLookupCompletesBeforeRequestIsWaiting() throws Exception {
        // i.e. the lookup has finished both phases when the request subscribes to it, as for a scheduler which is idle or runs the task directly
        JwtReactiveAuthenticationManager manager = manager(new ReactiveJwtMonoConverter(processor(), selector(), Schedulers.immediate()));
        authenticate(manager, token(key)).block(Duration.ofSeconds(10));
        int lookups = source.threads.size();

        source.refreshed = new JWKSet(List.of(key, otherKey));
        authenticate(manager, token(otherKey)).block(Duration.ofSeconds(10));
        assertThat(source.threads).hasSize(lookups + 3);

        source.refreshed = new JWKSet(List.of(key, otherKey));
        assertThatThrownBy(() -> authenticate(manager, token(thirdKey)).block(Duration.ofSeconds(10))).isInstanceOf(InvalidBearerTokenException.class);
        assertThat(source.threads).hasSize(lookups + 6);
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

    // wait for the lookup to publish its result, so that it does not interfere with what follows
    private void awaitFinishedLookups(int count) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 10_000;
        while (jwtScheduler.finished.get() < count && System.currentTimeMillis() < deadline) {
            Thread.sleep(10);
        }
        assertThat(jwtScheduler.finished.get()).isEqualTo(count);
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
