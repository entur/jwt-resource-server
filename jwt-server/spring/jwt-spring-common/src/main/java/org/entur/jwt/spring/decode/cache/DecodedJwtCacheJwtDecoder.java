package org.entur.jwt.spring.decode.cache;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSetBasedJWKSource;
import com.nimbusds.jose.jwk.source.JWKSetCacheRefreshEvaluator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import org.entur.jwt.spring.decode.JwtDecodingErrors;
import org.entur.jwt.spring.properties.jwk.JwtDecoderCacheMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import java.io.Closeable;
import java.text.ParseException;
import java.time.Instant;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.LongAdder;

/**
 * Caching of validated JWTs.
 * <br><br>
 * A cached JWT is only returned while the JWK set still holds the keys it was verified with: on every cache hit,
 * the keys matching the JWT's header are selected from the JWK source (normally from its cache, i.e. no remote call)
 * and compared with the keys selected when the JWT was verified. So the cache follows the JWK set, i.e. key rotation,
 * revocation and outages, like decoding without the cache does.
 * <br><br>
 * The JWK source must be the one which the delegate decoder verifies signatures with, selecting keys like
 * {@link com.nimbusds.jose.proc.JWSVerificationKeySelector} (i.e. {@link JWKMatcher#forJWSHeader(JWSHeader)}),
 * and should cache the JWK set.
 */
public class DecodedJwtCacheJwtDecoder implements JwtDecoder, Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(DecodedJwtCacheJwtDecoder.class);

    public static final String DEFAULT_CLEANUP_THREAD_NAME = "decoded-jwt-cache-cleanup";

    public static ScheduledExecutorService createDefaultScheduledExecutorService() {
        return createDefaultScheduledExecutorService(DEFAULT_CLEANUP_THREAD_NAME);
    }

    public static ScheduledExecutorService createDefaultScheduledExecutorService(String threadName) {
        // daemon thread so that a decoder which is never closed does not block JVM shutdown
        return Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, threadName);
            thread.setDaemon(true);
            return thread;
        });
    }

    // shared with other decoders (see constructor), or else created lazily (on scheduling cleanup or on the first eviction)
    // so instances which need neither don't spin up an unused background thread
    protected volatile ScheduledExecutorService scheduledExecutorService;
    // a shared executor is shut down by its owner, not by close()
    protected final boolean sharedScheduledExecutorService;
    // the periodic cleanup task, if scheduled (see scheduleCleanup())
    protected ScheduledFuture<?> cleanupTask;
    protected volatile boolean closed = false;

    protected static class Entry {
        protected final Jwt jwt;
        // selects the JWT's verification keys from the JWK set
        protected final JWKSelector keySelector;
        // the keys the JWT was verified with (one of them)
        protected final List<JWK> keys;
        // insertion order, for FIFO eviction
        protected final long sequence;
        // last access time (millis), for LRU eviction
        protected volatile long accessed;

        protected Entry(Jwt jwt, JWKSelector keySelector, List<JWK> keys, long sequence, long accessed) {
            this.jwt = jwt;
            this.keySelector = keySelector;
            this.keys = keys;
            this.sequence = sequence;
            this.accessed = accessed;
        }
    }

    protected static class Cache {

        // upper bound for the initial capacity of the token map
        protected static final int MAX_INITIAL_CAPACITY = 1 << 16;

        // when full (FIFO / LRU), evict down to this percentage of the target size, so the cost of
        // finding the entries to evict is amortized over many subsequent additions
        protected static final int EVICTION_TARGET_PERCENT = 90;

        // max number of histogram buckets used to find the entries to evict
        protected static final int HISTOGRAM_BUCKETS = 128;

        protected final ConcurrentHashMap<String, Entry> map;
        protected final int maxCacheSize;
        protected final JwtDecoderCacheMode mode;

        protected final AtomicLong sequence = new AtomicLong();

        // background eviction (FIFO / LRU)
        protected final Executor evictionExecutor;
        protected final AtomicBoolean evictionScheduled = new AtomicBoolean();

        protected volatile boolean fullWarningLogged = false;

        // total number of evicted JWTs
        protected final LongAdder evictions = new LongAdder();

        protected Cache(int maxCacheSize, JwtDecoderCacheMode mode, Executor evictionExecutor) {
            if(maxCacheSize == -1) {
                this.map = new ConcurrentHashMap<>();
                this.maxCacheSize = Integer.MAX_VALUE;
            } else {
                // pre-size for small caches only: the table is allocated up front, so a large size would cost a lot of memory
                this.map = new ConcurrentHashMap<>((int) Math.min(2L * maxCacheSize, MAX_INITIAL_CAPACITY));
                this.maxCacheSize = maxCacheSize;
            }
            this.mode = mode;
            this.evictionExecutor = evictionExecutor;
        }

        public void add(String token, Jwt jwt, JWKSelector keySelector, List<JWK> keys) {
            // the size checks are not atomic with the put, but it is good enough for this use case.
            int size = map.size();
            boolean evict = size >= maxCacheSize;
            if(evict) {
                if(!isEvicting()) {
                    warnFull();
                    return;
                }
                if(size >= getHardMaxCacheSize()) {
                    // if eviction was already scheduled, it does not keep up
                    if(!scheduleEviction()) {
                        warnFull();
                    }
                    return;
                }
                // temporarily exceed the target size, evict in the background
                // (after adding, so that the eviction accounts for this entry)
            }
            map.put(token, new Entry(jwt, keySelector, keys, sequence.incrementAndGet(), System.currentTimeMillis()));
            if(evict) {
                scheduleEviction();
            }
        }

        protected boolean isEvicting() {
            return mode != JwtDecoderCacheMode.FIXED && evictionExecutor != null && maxCacheSize > 0;
        }

        /**
         * With eviction, the target size may temporarily be exceeded until the background eviction has run;
         * do not grow without bound if eviction does not keep up.
         */
        protected int getHardMaxCacheSize() {
            return maxCacheSize > Integer.MAX_VALUE / 2 ? Integer.MAX_VALUE : maxCacheSize * 2;
        }

        protected void warnFull() {
            if(!fullWarningLogged && maxCacheSize > 0) {
                fullWarningLogged = true;
                if(mode == JwtDecoderCacheMode.FIXED) {
                    LOGGER.warn("Decoded JWT cache is full ({} JWTs), new JWTs are not cached until cached JWTs are no longer valid. Consider increasing the size or using another cache mode.", maxCacheSize);
                } else {
                    LOGGER.warn("Decoded JWT cache eviction does not keep up, cache is at {} JWTs (target size {}); new JWTs are not cached until eviction has run.", map.size(), maxCacheSize);
                }
            }
        }

        /**
         * @return true if eviction was scheduled by this call, false if already scheduled (or the decoder is closed)
         */
        protected boolean scheduleEviction() {
            if(evictionScheduled.compareAndSet(false, true)) {
                try {
                    evictionExecutor.execute(this::evict);
                    return true;
                } catch (RejectedExecutionException e) {
                    // decoder closed
                    evictionScheduled.set(false);
                }
            }
            return false;
        }

        /**
         * Evict entries with the lowest order (sequence for FIFO, last access time for LRU),
         * leaving at most {@link #EVICTION_TARGET_PERCENT} of the target size (but at least one entry).
         */
        protected void evict() {
            try {
                int target = Math.max(1, (int) ((long) maxCacheSize * EVICTION_TARGET_PERCENT / 100));
                int count = map.size() - target;
                if(count > 0) {
                    int evicted = evict(count);
                    evictions.add(evicted);
                    if (LOGGER.isDebugEnabled()) LOGGER.debug("Evicted {} JWTs from decoded JWT cache ({} in total), now have {}", evicted, evictions.sum(), map.size());
                }
            } catch (Throwable e) {
                LOGGER.warn("Problem evicting JWTs from cache", e);
            } finally {
                evictionScheduled.set(false);
            }
            // JWTs added while evicting might again exceed the target size
            if(map.size() > maxCacheSize) {
                scheduleEviction();
            }
        }

        /**
         * Evict (at most) the given number of entries with the lowest order, approximately:
         * the orders are counted into a histogram (between the min and max order), to find the bucket
         * holding the limit. Entries in lower buckets are evicted; within the limit bucket, whichever entries
         * the iterator covers first. Linear time, and no sorting or copying of the entries.
         *
         * @return the number of evicted entries
         */
        protected int evict(int count) {
            // pass 1: range of orders
            long min = Long.MAX_VALUE;
            long max = Long.MIN_VALUE;
            int n = 0;
            for (Entry entry : map.values()) {
                long order = order(entry);
                if(order < min) {
                    min = order;
                }
                if(order > max) {
                    max = order;
                }
                n++;
            }
            if(n == 0) {
                return 0;
            }

            // pass 2: histogram
            int buckets = Math.min(n, HISTOGRAM_BUCKETS);
            long width = (max - min) / buckets + 1;
            int[] histogram = new int[buckets];
            for (Entry entry : map.values()) {
                histogram[bucket(order(entry), min, width, buckets)]++;
            }

            // find the bucket holding the limit, and how many to evict from it
            int limitBucket = 0;
            int remaining = count;
            while (limitBucket < buckets - 1 && histogram[limitBucket] < remaining) {
                remaining -= histogram[limitBucket];
                limitBucket++;
            }

            // pass 3: evict everything below the limit bucket, and the first entries in the limit bucket
            int evicted = 0;
            Iterator<Entry> iterator = map.values().iterator();
            while (iterator.hasNext() && evicted < count) {
                int bucket = bucket(order(iterator.next()), min, width, buckets);
                if(bucket < limitBucket) {
                    iterator.remove();
                    evicted++;
                } else if(bucket == limitBucket && remaining > 0) {
                    iterator.remove();
                    evicted++;
                    remaining--;
                }
            }
            return evicted;
        }

        protected static int bucket(long order, long min, long width, int buckets) {
            // orders might have changed since the range was determined (i.e. LRU access, new entries)
            if(order <= min) {
                return 0;
            }
            long bucket = (order - min) / width;
            return bucket >= buckets ? buckets - 1 : (int) bucket;
        }

        protected long order(Entry entry) {
            return mode == JwtDecoderCacheMode.LRU ? entry.accessed : entry.sequence;
        }

        public Entry get(String token) {
            Entry entry = map.get(token);
            if(entry == null) {
                return null;
            }
            if(mode == JwtDecoderCacheMode.LRU) {
                // avoid writing (cache line contention) more than once per millisecond
                long now = System.currentTimeMillis();
                if(entry.accessed != now) {
                    entry.accessed = now;
                }
            }
            return entry;
        }

        public void remove(String token) {
            map.remove(token);
        }

        public void clear() {
            map.clear();
        }

        /**
         * Remove expired JWTs. Only the expiry is checked (not the validators, which might have side effects
         * or need a request): this is just to free memory, as cached JWTs are validated on every cache hit anyway.
         */
        protected int removeExpiredJwts(Instant now) {
            int count = 0;
            for (Map.Entry<String, Entry> entry : map.entrySet()) {
                Instant expiresAt = entry.getValue().jwt.getExpiresAt();
                if (expiresAt != null && expiresAt.isBefore(now) && map.remove(entry.getKey(), entry.getValue())) {
                    count++;
                }
            }
            return count;
        }

        public boolean isEmpty() {
            return map.isEmpty();
        }

        public int size() {
            return map.size();
        }
    }

    // i.e. the issuer; used to name the background thread. Optional.
    protected final String name;

    protected final JwtDecoder jwtValidatingDecoder;
    protected final JWKSource<SecurityContext> jwkSource;
    protected final OAuth2TokenValidator<Jwt> jwtValidator;

    protected final long cleanupInterval;
    protected final int maxCacheSize;
    protected final JwtDecoderCacheMode mode;

    protected final Cache cache;

    /**
     * Create a decoder using {@link JwtDecoderCacheMode#LRU} mode, the same default as the Spring configuration.
     */
    public DecodedJwtCacheJwtDecoder(JwtDecoder jwtValidatingDecoder, JWKSource<SecurityContext> jwkSource, OAuth2TokenValidator<Jwt> jwtValidators, long cleanupIntervalMillis, int maxCacheSize) {
        this(jwtValidatingDecoder, jwkSource, jwtValidators, cleanupIntervalMillis, maxCacheSize, JwtDecoderCacheMode.LRU);
    }

    public DecodedJwtCacheJwtDecoder(JwtDecoder jwtValidatingDecoder, JWKSource<SecurityContext> jwkSource, OAuth2TokenValidator<Jwt> jwtValidators, long cleanupIntervalMillis, int maxCacheSize, JwtDecoderCacheMode mode) {
        this(null, jwtValidatingDecoder, jwkSource, jwtValidators, cleanupIntervalMillis, maxCacheSize, mode);
    }

    /**
     * @param name name of this cache, i.e. the issuer; used to name its own background thread. Can be null.
     * @param jwtValidatingDecoder decoder which verifies and validates JWTs which are not cached
     * @param jwkSource the JWK source which the decoder verifies signatures with
     */
    public DecodedJwtCacheJwtDecoder(String name, JwtDecoder jwtValidatingDecoder, JWKSource<SecurityContext> jwkSource, OAuth2TokenValidator<Jwt> jwtValidators, long cleanupIntervalMillis, int maxCacheSize, JwtDecoderCacheMode mode) {
        this(name, jwtValidatingDecoder, jwkSource, jwtValidators, cleanupIntervalMillis, maxCacheSize, mode, null);
    }

    /**
     * @param name name of this cache, i.e. the issuer; used to name its own background thread. Can be null.
     * @param jwtValidatingDecoder decoder which verifies and validates JWTs which are not cached
     * @param jwkSource the JWK source which the decoder verifies signatures with
     * @param scheduledExecutorService executor for cleanup and eviction, i.e. shared by the decoders of several issuers,
     *                                 and shut down by the caller (not by {@link #close()}); or null to create one when needed
     */
    public DecodedJwtCacheJwtDecoder(String name, JwtDecoder jwtValidatingDecoder, JWKSource<SecurityContext> jwkSource, OAuth2TokenValidator<Jwt> jwtValidators, long cleanupIntervalMillis, int maxCacheSize, JwtDecoderCacheMode mode, ScheduledExecutorService scheduledExecutorService) {
        if (maxCacheSize < -1) {
            throw new IllegalArgumentException("maxCacheSize must be -1 (unlimited) or non-negative, was " + maxCacheSize);
        }
        if (mode == null) {
            throw new IllegalArgumentException("mode must not be null");
        }
        if (jwkSource == null) {
            throw new IllegalArgumentException("jwkSource must not be null");
        }
        this.name = name;
        this.jwtValidatingDecoder = jwtValidatingDecoder;
        this.jwkSource = jwkSource;
        this.jwtValidator = jwtValidators;
        this.cleanupInterval = cleanupIntervalMillis;
        this.maxCacheSize = maxCacheSize;
        this.mode = mode;
        this.scheduledExecutorService = scheduledExecutorService;
        this.sharedScheduledExecutorService = scheduledExecutorService != null;

        cache = new Cache(maxCacheSize, mode, this::executeInBackground);
    }

    /**
     * Schedule periodic cleanup of invalid (i.e. expired) cached JWTs. Idempotent: at most one cleanup task is scheduled.
     *
     * @return true if cleanup was scheduled by this call, false if already scheduled or the cleanup interval is not positive
     */
    public synchronized boolean scheduleCleanup() {
        if (cleanupInterval <= 0) {
            return false;
        }
        if (cleanupTask != null && !cleanupTask.isDone()) {
            return false;
        }
        cleanupTask = getScheduledExecutorService().scheduleWithFixedDelay(this::cleanup, cleanupInterval, cleanupInterval, TimeUnit.MILLISECONDS);
        return true;
    }

    protected synchronized ScheduledExecutorService getScheduledExecutorService() {
        if (closed) {
            throw new RejectedExecutionException("Closed");
        }
        if (scheduledExecutorService == null) {
            scheduledExecutorService = createDefaultScheduledExecutorService(getCleanupThreadName());
        }
        return scheduledExecutorService;
    }

    protected String getCleanupThreadName() {
        if (name == null || name.isEmpty()) {
            return DEFAULT_CLEANUP_THREAD_NAME;
        }
        return DEFAULT_CLEANUP_THREAD_NAME + "-" + name;
    }

    public String getName() {
        return name;
    }

    // run eviction on the (single) background thread, also used for cleanup
    protected void executeInBackground(Runnable command) {
        ScheduledExecutorService executor = scheduledExecutorService; // defensive copy
        if (executor == null || closed) {
            executor = getScheduledExecutorService(); // throws if closed
        }
        executor.execute(command);
    }

    public void cleanup() {
        if(!cache.isEmpty()) {
            try {
                // avoid memory leaks due to stagnant JWTs
                int cleaned = cache.removeExpiredJwts(Instant.now());
                if(cleaned > 0) {
                    if (LOGGER.isDebugEnabled()) LOGGER.debug("Cleaned {} expired JWTs from cache, now have {}", cleaned, cache.size());
                }
            } catch (Throwable e) {
                // ignore, will be handled by regular flow
                LOGGER.warn("Problem cleaning cache", e);
            }
        }
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        if (closed) {
            return jwtValidatingDecoder.decode(token);
        }
        Entry entry = cache.get(token);
        if (entry != null) {
            if (hasKeys(entry)) {
                // we have a cache hit, is it still valid?
                return validateJwt(entry.jwt);
            }
            // the JWK set no longer holds the keys the JWT was verified with, i.e. a key was rotated or revoked
            cache.remove(token);
        }

        JWKSelector keySelector = getKeySelector(token);
        List<JWK> keys = keySelector != null ? getKeys(keySelector) : null;

        Jwt jwt = jwtValidatingDecoder.decode(token); // also validates

        // Only add if the keys did not change while decoding: the decoder might otherwise have verified the
        // JWT using the previous JWK set, i.e. with a key which has since been replaced under the same key id.
        if (keys != null && !keys.isEmpty() && isSameKeys(keys, getKeys(keySelector))) {
            add(token, jwt, keySelector, keys);
        }

        return jwt;
    }

    /**
     * Add to the cache, unless closed: atomic with {@link #close()}, so that a decode which was in progress
     * when the decoder was closed does not repopulate the (cleared) cache.
     */
    protected synchronized void add(String token, Jwt jwt, JWKSelector keySelector, List<JWK> keys) {
        if (!closed) {
            cache.add(token, jwt, keySelector, keys);
        }
    }

    /**
     * @return true if the JWK set still holds the keys the cached JWT was verified with
     */
    protected boolean hasKeys(Entry entry) {
        List<JWK> keys = getKeys(entry.keySelector);
        // compare by value, so that cached JWTs are kept if the JWK set is reloaded with the same keys
        return keys != null && keys.containsAll(entry.keys);
    }

    /**
     * @return a selector for the keys which the JWT can be verified with, or null if the token is not a supported JWS
     */
    protected JWKSelector getKeySelector(String token) {
        int index = token.indexOf('.');
        if (index <= 0) {
            return null;
        }
        try {
            JWKMatcher matcher = JWKMatcher.forJWSHeader(JWSHeader.parse(new Base64URL(token.substring(0, index))));
            if (matcher != null) {
                return new JWKSelector(matcher);
            }
        } catch (ParseException e) {
            // not a JWS, the delegate decoder reports the problem
        }
        return null;
    }

    /**
     * @return the matching keys from the JWK set, or null if the JWK set is not available
     */
    protected List<JWK> getKeys(JWKSelector keySelector) {
        try {
            if (jwkSource instanceof JWKSetBasedJWKSource<SecurityContext> jwkSetBasedJWKSource) {
                // select from the (cached) JWK set, without the refresh which JWKSource.get(..) does if no key
                // matches; the delegate decoder does that refresh when it verifies the JWT
                JWKSet jwkSet = jwkSetBasedJWKSource.getJWKSetSource().getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), System.currentTimeMillis(), null);
                return keySelector.select(jwkSet);
            }
            return jwkSource.get(keySelector, null);
        } catch (Exception e) {
            // i.e. the JWK set is not available; the delegate decoder reports the problem
            if (LOGGER.isDebugEnabled()) LOGGER.debug("Unable to get JWKs for decoded JWT cache", e);
            return null;
        }
    }

    /**
     * @return true if both lists hold the same key instances, i.e. were selected from the same JWK set
     */
    protected static boolean isSameKeys(List<JWK> keys, List<JWK> otherKeys) {
        if (otherKeys == null || keys.size() != otherKeys.size()) {
            return false;
        }
        for (int i = 0; i < keys.size(); i++) {
            if (keys.get(i) != otherKeys.get(i)) {
                return false;
            }
        }
        return true;
    }

    protected Jwt validateJwt(Jwt jwt) {
        OAuth2TokenValidatorResult result = jwtValidator.validate(jwt);
        if (result.hasErrors()) {
            cache.remove(jwt.getTokenValue());

            Collection<OAuth2Error> errors = result.getErrors();
            String validationErrorString = getJwtValidationExceptionMessage(errors);
            throw new JwtValidationException(validationErrorString, errors);
        }
        return jwt;
    }

    protected String getJwtValidationExceptionMessage(Collection<OAuth2Error> errors) {
        return JwtDecodingErrors.validationErrorMessage(errors);
    }

    public void clear() {
        cache.clear();
    }

    /**
     * Stop the background cleanup and clear the cache. JWTs are still decoded (by the delegate decoder), but not cached.
     */
    public synchronized void close() {
        closed = true;
        if (cleanupTask != null) {
            cleanupTask.cancel(false);
        }
        ScheduledExecutorService executor = scheduledExecutorService; // defensive copy
        if (executor != null && !sharedScheduledExecutorService) {
            executor.shutdownNow();
        }
        cache.clear();
    }

    public int getSize() {
        return cache.size();
    }

    /**
     * @return total number of JWTs evicted to make room for new JWTs ({@link JwtDecoderCacheMode#FIFO} / {@link JwtDecoderCacheMode#LRU}).
     * A steadily increasing count means the cache churns; consider a larger size or {@link JwtDecoderCacheMode#FIXED}.
     */
    public long getEvictionCount() {
        return cache.evictions.sum();
    }
}
