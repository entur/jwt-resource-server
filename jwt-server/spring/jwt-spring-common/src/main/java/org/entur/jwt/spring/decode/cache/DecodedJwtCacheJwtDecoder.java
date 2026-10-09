package org.entur.jwt.spring.decode.cache;

import com.nimbusds.jose.jwk.JWKSet;
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
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.LongAdder;

/**
 * Caching of validated JWTs.
 * <br><br>
 * Must be kept up to date with the JWK set via {@link #updateKeys(JWKSet)}, and suspended while the JWK set can
 * no longer be trusted via {@link #suspendAt(long)} / {@link #resume()}; i.e. by registering a {@link DecodedJwtCacheJwkEventListener}
 * with the JWK source. Make sure to proactively (eagerly) refresh the JWK set, so that key rotation is detected.
 */
public class DecodedJwtCacheJwtDecoder implements JwtDecoder, Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(DecodedJwtCacheJwtDecoder.class);

    public static ScheduledExecutorService createDefaultScheduledExecutorService() {
        // daemon thread so that a decoder which is never closed does not block JVM shutdown
        return Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "decoded-jwt-cache-cleanup");
            thread.setDaemon(true);
            return thread;
        });
    }

    // created lazily (on scheduling cleanup or on the first eviction) so instances which need neither don't spin up an unused background thread
    protected volatile ScheduledExecutorService scheduledExecutorService;
    protected volatile boolean closed = false;

    protected static class Entry {
        protected final Jwt jwt;
        // insertion order, for FIFO eviction
        protected final long sequence;
        // last access time (millis), for LRU eviction
        protected volatile long accessed;

        protected Entry(Jwt jwt, long sequence, long accessed) {
            this.jwt = jwt;
            this.sequence = sequence;
            this.accessed = accessed;
        }
    }

    protected static class Cache {

        // when full (FIFO / LRU), evict down to this percentage of the target size, so the cost of
        // finding the entries to evict is amortized over many subsequent additions
        protected static final int EVICTION_TARGET_PERCENT = 90;

        // max number of histogram buckets used to find the entries to evict
        protected static final int HISTOGRAM_BUCKETS = 128;

        protected final ConcurrentHashMap<String, Entry> map;
        // active keys at the time this cache was created, so that any refresh which
        // changes key selection-relevant metadata while keeping the same kid is detected
        protected final DecodedJwtCacheJWKRepresentations keyRepresentations;
        protected final int maxCacheSize;
        protected final JwtDecoderCacheMode mode;
        protected final OAuth2TokenValidator<Jwt> jwtValidator;

        protected final AtomicLong sequence = new AtomicLong();

        // background eviction (FIFO / LRU)
        protected final Executor evictionExecutor;
        protected final AtomicBoolean evictionScheduled = new AtomicBoolean();

        protected volatile boolean fullWarningLogged = false;

        // total number of evicted JWTs, shared by all cache instances of a decoder
        protected final LongAdder evictions;

        protected Cache(DecodedJwtCacheJWKRepresentations keyRepresentations, int maxCacheSize, JwtDecoderCacheMode mode, OAuth2TokenValidator<Jwt> jwtValidator, Executor evictionExecutor) {
            this(keyRepresentations, maxCacheSize, mode, jwtValidator, evictionExecutor, new LongAdder());
        }

        protected Cache(DecodedJwtCacheJWKRepresentations keyRepresentations, int maxCacheSize, JwtDecoderCacheMode mode, OAuth2TokenValidator<Jwt> jwtValidator, Executor evictionExecutor, LongAdder evictions) {
            this.keyRepresentations = keyRepresentations;
            this.evictions = evictions;
            if(maxCacheSize == -1) {
                this.map = new ConcurrentHashMap<>();
                this.maxCacheSize = Integer.MAX_VALUE;
            } else {
                this.map = new ConcurrentHashMap<>(2 * maxCacheSize);
                this.maxCacheSize = maxCacheSize;
            }
            this.mode = mode;
            this.jwtValidator = jwtValidator;
            this.evictionExecutor = evictionExecutor;
        }

        public void add(String token, Jwt jwt) {
            if (!isKeyKnown(jwt)) {
                return;
            }
            // the size checks are not atomic with the put, but it is good enough for this use case.
            int size = map.size();
            boolean evict = size >= maxCacheSize;
            if(evict) {
                if(!isEvicting()) {
                    warnFull();
                    return;
                }
                if(size >= getHardMaxCacheSize()) {
                    // i.e. after migrating a full cache on a JWK set change, nothing else might have scheduled eviction;
                    // if eviction was already scheduled, it does not keep up
                    if(!scheduleEviction()) {
                        warnFull();
                    }
                    return;
                }
                // temporarily exceed the target size, evict in the background
                // (after adding, so that the eviction accounts for this entry)
            }
            map.put(token, new Entry(jwt, sequence.incrementAndGet(), System.currentTimeMillis()));
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
         * leaving at most {@link #EVICTION_TARGET_PERCENT} of the target size.
         */
        protected void evict() {
            try {
                int target = (int) ((long) maxCacheSize * EVICTION_TARGET_PERCENT / 100);
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

        public Jwt get(String token) {
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
            return entry.jwt;
        }

        public void remove(String token) {
            map.remove(token);
        }

        public void clear() {
            map.clear();
        }

        /**
         * @return true if the JWT's key id is present in this cache's own snapshot of
         * active key ids ({@link #keyRepresentations}), taken when this cache instance
         * was created (i.e. as of the last processed JWKS refresh at that time).
         */
        protected boolean isKeyKnown(Jwt jwt) {
            String kid = (String) jwt.getHeaders().get("kid");
            return kid != null && keyRepresentations.contains(kid);
        }

        protected int cleanInvalidJwts() {
            int count = 0;
            // remove no longer valid JWTs. Typically they expire by time.
            for (Map.Entry<String, Entry> entry : map.entrySet()) {
                Entry value = entry.getValue();
                if(value != null) {
                    OAuth2TokenValidatorResult result = jwtValidator.validate(value.jwt);
                    if (result.hasErrors()) {
                        map.remove(entry.getKey());
                        count++;
                    }
                }
            }
            return count;
        }

        public boolean hasSameKeys(DecodedJwtCacheJWKRepresentations keyRepresentations) {
            return this.keyRepresentations.hasSameKeys(keyRepresentations);
        }

        /**
         * Migrate still-cached JWTs from the (previous) {@code cache}, only carrying over
         * entries whose kid is in {@code keyIdsToKeep} - the whitelist of key ids proven
         * unchanged between the previous and this cache's key set. Anything not in this
         * set (added, removed, or changed keys, including any key sharing a kid with
         * several JWKs where at least one of them differs) is dropped.
         */
        public void add(Cache cache, Set<String> keyIdsToKeep) {
            if (keyIdsToKeep.isEmpty()) {
                return; // nothing can match, avoid iterating the old cache at all
            }
            // keep the insertion order for FIFO
            sequence.set(cache.sequence.get());

            // with eviction (FIFO / LRU) the previous cache might temporarily hold more than the target size;
            // copy up to the hard max size, and leave it to the background eviction (triggered by the next
            // addition) to pick what to remove, so the entries which are kept follow the cache mode rather
            // than the (arbitrary) iteration order
            int limit = isEvicting() ? getHardMaxCacheSize() : maxCacheSize;
            for (Map.Entry<String, Entry> entry : cache.map.entrySet()) {
                // bail out as soon as capacity is reached instead of checking size per-entry
                if (map.size() >= limit) {
                    return;
                }
                Entry value = entry.getValue();
                if (value == null) {
                    continue;
                }
                String kid = (String) value.jwt.getHeaders().get("kid");
                // only migrate entries whose key id was positively confirmed unchanged; a
                // kid re-used for a rotated/different key must not carry over previously
                // cached/validated JWTs
                if (kid != null && keyIdsToKeep.contains(kid)) {
                    map.put(entry.getKey(), value);
                }
            }
        }

        public boolean isEmpty() {
            return map.isEmpty();
        }

        public int size() {
            return map.size();
        }
    }

    protected final JwtDecoder jwtValidatingDecoder;
    protected final OAuth2TokenValidator<Jwt> jwtValidator;

    protected final long cleanupInterval;
    protected final int maxCacheSize;
    protected final JwtDecoderCacheMode mode;

    protected static final long NEVER = Long.MAX_VALUE;

    // from when the cache is not used, checked when decoding (see suspendAt(..))
    protected volatile long suspendedAt = NEVER;

    protected volatile Cache cache;

    // total number of JWTs evicted to make room for new JWTs (FIFO / LRU)
    protected final LongAdder evictions = new LongAdder();

    /**
     * Create a decoder using {@link JwtDecoderCacheMode#LRU} mode, the same default as the Spring configuration.
     */
    public DecodedJwtCacheJwtDecoder(JwtDecoder jwtValidatingDecoder, OAuth2TokenValidator<Jwt> jwtValidators, long cleanupIntervalMillis, int maxCacheSize) {
        this(jwtValidatingDecoder, jwtValidators, cleanupIntervalMillis, maxCacheSize, JwtDecoderCacheMode.LRU);
    }

    public DecodedJwtCacheJwtDecoder(JwtDecoder jwtValidatingDecoder, OAuth2TokenValidator<Jwt> jwtValidators, long cleanupIntervalMillis, int maxCacheSize, JwtDecoderCacheMode mode) {
        if (maxCacheSize < -1) {
            throw new IllegalArgumentException("maxCacheSize must be -1 (unlimited) or non-negative, was " + maxCacheSize);
        }
        if (mode == null) {
            throw new IllegalArgumentException("mode must not be null");
        }
        this.jwtValidatingDecoder = jwtValidatingDecoder;
        this.jwtValidator = jwtValidators;
        this.cleanupInterval = cleanupIntervalMillis;
        this.maxCacheSize = maxCacheSize;
        this.mode = mode;

        cache = new Cache(DecodedJwtCacheJWKRepresentations.empty(), 0, mode, jwtValidator, null);
    }

    public synchronized void scheduleCleanup() {
        if (cleanupInterval <= 0) {
            return;
        }
        getScheduledExecutorService().scheduleWithFixedDelay(this::cleanup, cleanupInterval, cleanupInterval, TimeUnit.MILLISECONDS);
    }

    protected synchronized ScheduledExecutorService getScheduledExecutorService() {
        if (closed) {
            throw new RejectedExecutionException("Closed");
        }
        if (scheduledExecutorService == null) {
            scheduledExecutorService = createDefaultScheduledExecutorService();
        }
        return scheduledExecutorService;
    }

    // run eviction on the (single) background thread, also used for cleanup
    protected void executeInBackground(Runnable command) {
        ScheduledExecutorService executor = scheduledExecutorService; // defensive copy
        if (executor == null) {
            executor = getScheduledExecutorService();
        }
        executor.execute(command);
    }

    public void cleanup() {
        if (isSuspended()) {
            cache.clear();
            return;
        }

        Cache c = this.cache; // defensive copy
        if(!c.isEmpty()) {
            try {
                // avoid memory leaks due to stagnant JWTs
                int cleaned = c.cleanInvalidJwts();
                if(cleaned > 0) {
                    if (LOGGER.isDebugEnabled()) LOGGER.debug("Cleaned {} invalid JWTs from cache, now have {}", cleaned, c.size());
                }
            } catch (Throwable e) {
                // ignore, will be handled by regular flow
                LOGGER.warn("Problem cleaning cache", e);
            }
        }
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        if (isSuspended()) {
            // decode as if no JWT was cached
            Cache c = this.cache;
            if (!c.isEmpty()) {
                c.clear();
            }
            return jwtValidatingDecoder.decode(token);
        }

        Cache c = this.cache; // defensive copy

        Jwt cachedJwt = c.get(token);
        if (cachedJwt != null) {
            // we have a cache hit, is it still valid?
            return validateJwt(cachedJwt, c);
        }

        Jwt jwt = jwtValidatingDecoder.decode(token); // also validates

        // Only add if no JWK set refresh completed while decoding: the decoder might have verified the
        // JWT using the previous JWK set, i.e. with a key which has since been replaced under the same key id.
        if (this.cache == c) {
            c.add(token, jwt); // only adds if the keyid is known
        }

        return jwt;
    }

    protected Jwt validateJwt(Jwt jwt, Cache c) {
        OAuth2TokenValidatorResult result = jwtValidator.validate(jwt);
        if (result.hasErrors()) {
            c.remove(jwt.getTokenValue());

            Collection<OAuth2Error> errors = result.getErrors();
            String validationErrorString = getJwtValidationExceptionMessage(errors);
            throw new JwtValidationException(validationErrorString, errors);
        }
        return jwt;
    }

    protected String getJwtValidationExceptionMessage(Collection<OAuth2Error> errors) {
        return JwtDecodingErrors.validationErrorMessage(errors);
    }

    // clears tokens, not key ids
    public void clear() {
        cache.clear();
    }

    /**
     * Update the cached key representations from a (re)loaded JWK set, evicting cached JWTs whose key was added,
     * removed or changed. Cached JWTs whose key is unchanged are kept.
     */
    public void updateKeys(JWKSet jwkSet) {
        Cache cache = this.cache; // defensive copy
        DecodedJwtCacheJWKRepresentations keyRepresentations = DecodedJwtCacheJWKRepresentations.of(jwkSet);

        // compare the full JWK representation for each kid, not just key id or
        // RFC 7638 thumbprint, so metadata changes affecting key selection also
        // invalidate previously cached JWTs.
        if(!cache.hasSameKeys(keyRepresentations)) {
            // keys were added, removed, or changed since the previous refresh; work
            // out which key ids are positively confirmed unchanged (a safe whitelist),
            // so only cached JWTs signed by those keys are migrated - everything else
            // is dropped by default rather than only excluded if provably changed
            Set<String> keyIdsToKeep = keyRepresentations.unchangedKeyIds(cache.keyRepresentations);

            Cache nextCache = new Cache(keyRepresentations, maxCacheSize, mode, jwtValidator, this::executeInBackground, evictions);
            nextCache.add(cache, keyIdsToKeep);
            this.cache = nextCache;
        }
    }

    /**
     * Stop using the cache from the given time: the cache is cleared, and JWTs are decoded as if no JWT
     * was cached, until {@link #resume()}. Checked when decoding (and on cleanup), so no timer is needed.
     *
     * @param timeMillis time (epoch millis) from which the cache is not used
     */
    public void suspendAt(long timeMillis) {
        this.suspendedAt = timeMillis;
    }

    /**
     * Use the cache again, cancelling any {@link #suspendAt(long)}.
     */
    public void resume() {
        this.suspendedAt = NEVER;
    }

    protected boolean isSuspended() {
        long suspendedAt = this.suspendedAt;
        return suspendedAt != NEVER && System.currentTimeMillis() >= suspendedAt;
    }

    public synchronized void close() {
        closed = true;
        ScheduledExecutorService executor = scheduledExecutorService; // defensive copy
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    public int getSize() {
        return cache.size();
    }

    /**
     * @return total number of JWTs evicted to make room for new JWTs ({@link JwtDecoderCacheMode#FIFO} / {@link JwtDecoderCacheMode#LRU}).
     * A steadily increasing count means the cache churns; consider a larger size or {@link JwtDecoderCacheMode#FIXED}.
     */
    public long getEvictionCount() {
        return evictions.sum();
    }
}
