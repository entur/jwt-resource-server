package org.entur.jwt.spring;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSetBasedJWKSource;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSetSourceWrapper;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RateLimitReachedException;
import com.nimbusds.jose.jwk.source.URLBasedJWKSetSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtException;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.security.Key;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * Reactive JWT processing for a single tenant.
 * <br><br>
 * Looking up the keys might block (i.e. while the JWK source fetches the keys), so lookups run on the scheduler,
 * at most one at a time. Requests waiting for a lookup do not hold a thread, and continue on a non-blocking thread.
 * The keys of a lookup are then used for verifying tokens on the calling thread, so that most requests need
 * no lookup at all.
 * <br><br>
 * The keys of a lookup are used for at most 10 seconds, and never for longer than the time-to-live of the JWK source cache
 * (so a removed key might be accepted for up to 10 seconds longer than the JWK source cache alone would). If the JWK source does not cache
 * (i.e. it fetches the keys on every call), or is not known to cache (i.e. it is not built by the JWK source builder of Nimbus), the keys are
 * not reused, so that only concurrent requests share a lookup.
 * <br><br>
 * The JWK source is read with a selector for all keys, and the keys for a token are then selected from the result. A JWK source which
 * restricts the keys by the criteria of the selector is therefore not supported.
 */

public class ReactiveJwtMonoConverter implements Converter<JWT, Mono<JWTClaimsSet>> {

    // use the keys of a lookup for this long (at most), and look them up again in the background after half of it.
    // Unknown keys are looked up right away, so this only delays the removal of keys
    private static final long MAX_KEYS_TIME_TO_LIVE = TimeUnit.SECONDS.toNanos(10);
    private static final long UNKNOWN_CACHE = -1;

    private static final JWKSelector ALL_KEYS = new JWKSelector(new JWKMatcher.Builder().build());

    // not the processor given to the constructor, as the JWS key selector is replaced
    private final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
    private final JWSVerificationKeySelector<SecurityContext> selector;
    private final Scheduler scheduler;
    // zero if the keys of a lookup are not reused
    private final long keysTimeToLive;
    // false if a refresh is pointless, i.e. the JWK source does not cache
    private final boolean refreshUnknownKeys;

    private final Object lock = new Object();
    // the lookup in progress, if any
    private Sinks.One<Keys> lookup;
    // the keys of the latest successful lookup
    private volatile Keys keys;

    public ReactiveJwtMonoConverter(DefaultJWTProcessor<SecurityContext> jwtProcessor, JWSVerificationKeySelector selector) {
        this(jwtProcessor, selector, Schedulers.boundedElastic());
    }

    /**
     * Construct new instance. The given JWT processor is not modified; its JWS type verifier, JWS verifier factory and claims verifier
     * are copied to an internal processor, which selects the keys from the keys looked up from the JWK source of the given selector.
     * The verifiers are called without security context.
     * <br><br>
     * As the keys are looked up in advance, custom key selection and processing is not supported: the JWT processor must be a
     * {@linkplain DefaultJWTProcessor} (not a subclass) without a JWS key selector (or the given selector as its JWS key selector), and the
     * selector must be a {@linkplain JWSVerificationKeySelector} (not a subclass).
     *
     * @param jwtProcessor JWT processor, for the configuration of the verification
     * @param selector key selector, for the JWK source and the allowed algorithms
     * @param scheduler scheduler for looking up the keys
     * @throws IllegalArgumentException if the key selection of the JWT processor or the selector is customized, or the JWT processor is a subclass
     */

    public ReactiveJwtMonoConverter(DefaultJWTProcessor<SecurityContext> jwtProcessor, JWSVerificationKeySelector selector, Scheduler scheduler) {
        // fail closed, as custom key selection or processing (i.e. an allowlist or revocation check) would otherwise be bypassed
        JWSKeySelector<SecurityContext> jwsKeySelector = jwtProcessor.getJWSKeySelector();
        if (jwtProcessor.getClass() != DefaultJWTProcessor.class || selector.getClass() != JWSVerificationKeySelector.class
                || (jwsKeySelector != null && jwsKeySelector != selector) || jwtProcessor.getJWTClaimsSetAwareJWSKeySelector() != null) {
            throw new IllegalArgumentException("Custom key selection and processing is not supported, as keys are selected from keys looked up in advance");
        }

        this.selector = selector;
        this.scheduler = scheduler;
        long cacheTimeToLive = cacheTimeToLive(selector.getJWKSource());
        // a JWK source which is not known to cache might still do so, so look up unknown keys (but do not reuse the keys of a lookup)
        this.keysTimeToLive = Math.max(0, Math.min(MAX_KEYS_TIME_TO_LIVE, cacheTimeToLive));
        this.refreshUnknownKeys = cacheTimeToLive != 0;

        // the verifiers do not receive the security context of this converter (the looked up keys)
        JOSEObjectTypeVerifier<SecurityContext> typeVerifier = jwtProcessor.getJWSTypeVerifier();
        this.processor.setJWSTypeVerifier(typeVerifier != null ? (type, context) -> typeVerifier.verify(type, null) : null);
        this.processor.setJWSVerifierFactory(jwtProcessor.getJWSVerifierFactory());
        JWTClaimsSetVerifier<SecurityContext> claimsVerifier = jwtProcessor.getJWTClaimsSetVerifier();
        this.processor.setJWTClaimsSetVerifier(claimsVerifier != null ? (claims, context) -> claimsVerifier.verify(claims, null) : null);
        // select from the keys of a lookup (passed as the security context), so that processing never blocks
        processor.setJWSKeySelector((header, context) -> {
            if (!this.selector.isAllowed(header.getAlgorithm())) {
                return List.of();
            }
            return ((Keys) context).select(header);
        });
    }

    @Override
    public Mono<JWTClaimsSet> convert(JWT source) {
        JWSHeader jwsHeader = (JWSHeader) source.getHeader();
        if (!selector.isAllowed(jwsHeader.getAlgorithm())) {
            throw new BadJwtException("Unsupported algorithm of " + jwsHeader.getAlgorithm());
        }

        return Mono.defer(() -> {
            Keys current = this.keys;
            long time = nanoTime();
            if (current != null && current.isValid(time) && current.contains(jwsHeader)) {
                if (current.isRefreshable(time)) {
                    // in the background
                    lookup(null);
                }
                return Mono.fromCallable(() -> createClaimsSet(source, current));
            }
            return keysFor(jwsHeader)
                    // continue (i.e. the security filter chain and the request handling) on a non-blocking thread,
                    // so that the scheduler is only used for lookups
                    .publishOn(Schedulers.parallel())
                    .map(k -> createClaimsSet(source, k));
        });
    }

    // a lookup in progress might be for another token, which does not look up unknown keys of this token.
    // So repeat until the keys contain the key, or are the result of a lookup for this token
    private Mono<Keys> keysFor(JWSHeader header) {
        return lookup(header).flatMap(k -> keysFor(header, k));
    }

    private Mono<Keys> keysFor(JWSHeader header, Keys keys) {
        if (keys.contains(header) || keys.isLookupFor(header)) {
            return Mono.just(keys);
        }
        // wait for the refresh of the lookup (which might already have finished) rather than start a new lookup
        return keys.refresh != null ? keys.refresh.flatMap(k -> keysFor(header, k)) : keysFor(header);
    }

    private Mono<Keys> lookup(JWSHeader header) {
        Sinks.One<Keys> sink;
        synchronized (lock) {
            if (lookup != null) {
                return lookup.asMono();
            }
            sink = Sinks.one();
            lookup = sink;
        }
        try {
            scheduler.schedule(() -> lookup(header, sink));
        } catch (RejectedExecutionException e) {
            // also for requests which are already waiting for this lookup
            complete(sink);
            sink.tryEmitError(new JwtException("Unable to look up keys", e));
        }
        return sink.asMono();
    }

    private void lookup(JWSHeader header, Sinks.One<Keys> sink) {
        // the sink of the current phase of the lookup, as the lookup is completed for waiting requests in two phases if a refresh is needed
        Sinks.One<Keys> current = sink;
        try {
            JWKSource<SecurityContext> jwkSource = selector.getJWKSource();

            long time = nanoTime();
            List<JWK> all = jwkSource.get(ALL_KEYS, null);

            JWKMatcher matcher = header != null && refreshUnknownKeys ? JWKMatcher.forJWSHeader(header) : null;
            if (matcher != null && all.stream().noneMatch(matcher::matches)) {
                // the keys at hand are enough for requests which do not need the unknown key (also those already waiting), so release
                // them right away. Requests for the unknown key look up again, which waits for the refresh in progress
                current = Sinks.one();
                Keys known = new Keys(new JWKSet(all), time, null, current.asMono());
                this.keys = known;
                synchronized (lock) {
                    lookup = current;
                }
                sink.tryEmitValue(known);
                try {
                    // unknown key, so that the JWK source refreshes its keys
                    jwkSource.get(new JWKSelector(matcher), null);
                    all = jwkSource.get(ALL_KEYS, null);
                } catch (RateLimitReachedException e) {
                    // use the keys at hand; any other failure is not hidden as an invalid token
                }
            }
            Keys result = new Keys(new JWKSet(all), time, header, null);
            this.keys = result;
            complete(current);
            current.tryEmitValue(result);
        } catch (Throwable e) {
            // always complete the lookup, so that later requests do not wait for a lookup which never finishes
            complete(current);
            current.tryEmitError(e instanceof RuntimeException r ? r : new JwtException("Failed to validate the token", e));
            Exceptions.throwIfJvmFatal(e);
        }
    }

    private void complete(Sinks.One<Keys> sink) {
        synchronized (lock) {
            if (lookup == sink) {
                lookup = null;
            }
        }
    }

    // the time to live of the JWK source cache in nanoseconds, zero if the JWK source does not cache (i.e. it fetches the keys
    // on every call), or UNKNOWN_CACHE if it is not known
    private static long cacheTimeToLive(JWKSource<SecurityContext> jwkSource) {
        if (jwkSource instanceof JWKSetBasedJWKSource<SecurityContext> jwkSetBasedJwkSource) {
            JWKSetSource<SecurityContext> source = jwkSetBasedJwkSource.getJWKSetSource();
            while (source instanceof JWKSetSourceWrapper<SecurityContext> wrapper) {
                if (wrapper instanceof CachingJWKSetSource<SecurityContext> caching) {
                    return TimeUnit.MILLISECONDS.toNanos(caching.getTimeToLive());
                }
                source = wrapper.getSource();
            }
            if (source instanceof URLBasedJWKSetSource) {
                return 0;
            }
        }
        return UNKNOWN_CACHE;
    }

    private JWTClaimsSet createClaimsSet(JWT parsedToken, Keys keys) {
        try {
            return processor.process(parsedToken, keys);
        } catch (BadJOSEException ex) {
            throw new BadJwtException("Failed to validate the token", ex);
        } catch (JOSEException ex) {
            throw new JwtException("Failed to validate the token", ex);
        }
    }

    protected long nanoTime() {
        return System.nanoTime();
    }

    private static boolean contains(List<JWK> keys, JWSHeader header) {
        JWKMatcher matcher = JWKMatcher.forJWSHeader(header);
        return matcher != null && keys.stream().anyMatch(matcher::matches);
    }

    // the keys of a lookup, passed as security context to the JWT processor
    private final class Keys implements SecurityContext {

        private final ImmutableJWKSet<SecurityContext> jwkSet;
        private final long time;
        // the token which the keys were looked up for, if any
        private final JWSHeader header;
        // the keys after the refresh, if the keys are those at hand while the JWK source refreshes for an unknown key
        private final Mono<Keys> refresh;

        private Keys(JWKSet jwkSet, long time, JWSHeader header, Mono<Keys> refresh) {
            this.jwkSet = new ImmutableJWKSet<>(jwkSet);
            this.time = time;
            this.header = header;
            this.refresh = refresh;
        }

        private boolean isValid(long time) {
            return time - this.time < keysTimeToLive;
        }

        private boolean isRefreshable(long time) {
            return time - this.time >= keysTimeToLive / 2;
        }

        private boolean contains(JWSHeader header) {
            return ReactiveJwtMonoConverter.contains(jwkSet.getJWKSet().getKeys(), header);
        }

        private boolean isLookupFor(JWSHeader header) {
            return this.header != null && this.header.getAlgorithm().equals(header.getAlgorithm()) && Objects.equals(this.header.getKeyID(), header.getKeyID());
        }

        private List<Key> select(JWSHeader header) throws KeySourceException {
            // i.e. the same selection as for the JWK source
            return new JWSVerificationKeySelector<>(header.getAlgorithm(), jwkSet).selectJWSKeys(header, null);
        }
    }
}
