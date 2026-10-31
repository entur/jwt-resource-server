package org.entur.jwt.spring;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
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
 */

public class ReactiveJwtMonoConverter implements Converter<JWT, Mono<JWTClaimsSet>> {

    // use the keys of a lookup for this long, and look them up again in the background after half of it.
    // Unknown keys are looked up right away, so this only delays the removal of keys
    private static final long KEYS_TIME_TO_LIVE = TimeUnit.SECONDS.toNanos(10);
    private static final long KEYS_REFRESH = KEYS_TIME_TO_LIVE / 2;

    private static final JWKSelector ALL_KEYS = new JWKSelector(new JWKMatcher.Builder().build());

    // not the processor given to the constructor, as the JWS key selector is replaced
    private final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
    private final JWSVerificationKeySelector<SecurityContext> selector;
    private final Scheduler scheduler;

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
     *
     * @param jwtProcessor JWT processor, for the configuration of the verification
     * @param selector key selector, for the JWK source and the allowed algorithms
     * @param scheduler scheduler for looking up the keys
     */

    public ReactiveJwtMonoConverter(DefaultJWTProcessor<SecurityContext> jwtProcessor, JWSVerificationKeySelector selector, Scheduler scheduler) {
        this.selector = selector;
        this.scheduler = scheduler;

        this.processor.setJWSTypeVerifier(jwtProcessor.getJWSTypeVerifier());
        this.processor.setJWSVerifierFactory(jwtProcessor.getJWSVerifierFactory());
        this.processor.setJWTClaimsSetVerifier(jwtProcessor.getJWTClaimsSetVerifier());
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
            return lookup(jwsHeader)
                    // a lookup started for another token does not look up unknown keys of this token
                    .flatMap(k -> k.contains(jwsHeader) || k.isLookupFor(jwsHeader) ? Mono.just(k) : lookup(jwsHeader))
                    // continue (i.e. the security filter chain and the request handling) on a non-blocking thread,
                    // so that the scheduler is only used for lookups
                    .publishOn(Schedulers.parallel())
                    .map(k -> createClaimsSet(source, k));
        });
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
        Keys result;
        try {
            result = getKeys(header);
        } catch (Throwable e) {
            // always complete the lookup, so that later requests do not wait for a lookup which never finishes
            complete(sink);
            sink.tryEmitError(e instanceof RuntimeException r ? r : new JwtException("Failed to validate the token", e));
            Exceptions.throwIfJvmFatal(e);
            return;
        }
        this.keys = result;
        complete(sink);
        sink.tryEmitValue(result);
    }

    private void complete(Sinks.One<Keys> sink) {
        synchronized (lock) {
            if (lookup == sink) {
                lookup = null;
            }
        }
    }

    private Keys getKeys(JWSHeader header) throws KeySourceException {
        JWKSource<SecurityContext> jwkSource = selector.getJWKSource();

        long time = nanoTime();
        List<JWK> all = jwkSource.get(ALL_KEYS, null);
        JWKMatcher matcher = header != null ? JWKMatcher.forJWSHeader(header) : null;
        if (matcher != null && all.stream().noneMatch(matcher::matches)) {
            // unknown key, so that the JWK source refreshes its keys
            try {
                jwkSource.get(new JWKSelector(matcher), null);
            } catch (KeySourceException e) {
                // i.e. rate limited, use the keys at hand
            }
            all = jwkSource.get(ALL_KEYS, null);
        }
        return new Keys(new JWKSet(all), time, header);
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
    private static final class Keys implements SecurityContext {

        private final ImmutableJWKSet<SecurityContext> jwkSet;
        private final long time;
        // the token which the keys were looked up for, if any
        private final JWSHeader header;

        private Keys(JWKSet jwkSet, long time, JWSHeader header) {
            this.jwkSet = new ImmutableJWKSet<>(jwkSet);
            this.time = time;
            this.header = header;
        }

        private boolean isValid(long time) {
            return time - this.time < KEYS_TIME_TO_LIVE;
        }

        private boolean isRefreshable(long time) {
            return time - this.time >= KEYS_REFRESH;
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
