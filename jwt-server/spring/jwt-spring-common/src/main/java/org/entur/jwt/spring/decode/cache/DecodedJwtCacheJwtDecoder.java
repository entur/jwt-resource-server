package org.entur.jwt.spring.decode.cache;

import com.nimbusds.jose.jwk.source.CachingJWKSetSource;
import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.util.StringUtils;

import java.io.Closeable;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Caching of validated JWTs.
 *
 * If used, make sure to proactively update JWKs somehow.
 *
 */
public class DecodedJwtCacheJwtDecoder implements JwtDecoder, EventListener, Closeable {

    private static final String DECODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to decode the Jwt: %s";

    private static final Logger LOGGER = LoggerFactory.getLogger(DecodedJwtCacheJwtDecoder.class);

    public static ScheduledExecutorService createDefaultScheduledExecutorService() {
        return Executors.newSingleThreadScheduledExecutor();
    }

    // created lazily so instances with cleanup disabled (cleanupInterval <= 0) don't spin up an unused background thread
    protected volatile ScheduledExecutorService scheduledExecutorService;

    protected static class Cache {
        protected final ConcurrentHashMap<String, Jwt> map;
        // active keys at the time this cache was created, so that any refresh which
        // changes key selection-relevant metadata while keeping the same kid is detected
        protected final DecodedJwtCacheJWKRepresentations keyRepresentations;
        protected final int maxCacheSize;
        protected final OAuth2TokenValidator<Jwt> jwtValidator;

        protected Cache(DecodedJwtCacheJWKRepresentations keyRepresentations, int maxCacheSize, OAuth2TokenValidator<Jwt> jwtValidator) {
            this.keyRepresentations = keyRepresentations;
            if(maxCacheSize == -1) {
                this.map = new ConcurrentHashMap<>();
                this.maxCacheSize = Integer.MAX_VALUE;
            } else {
                this.map = new ConcurrentHashMap<>(2 * maxCacheSize);
                this.maxCacheSize = maxCacheSize;
            }
            this.jwtValidator = jwtValidator;
        }

        public void add(String token, Jwt jwt) {
            // the size check is not atomic with the put, but it is good enough for this use case.
            if(map.size() >= maxCacheSize) {
                return;
            }

            String kid = (String)jwt.getHeaders().get("kid");
            if(kid != null && keyRepresentations.contains(kid)) {
                map.put(token, jwt);
            }
        }

        public Jwt get(String token) {
            return map.get(token);
        }

        public void remove(String token) {
            map.remove(token);
        }

        public void clear() {
            map.clear();
        }

        protected int cleanInvalidJwts() {
            int count = 0;
            // remove no longer valid JWTs. Typically they expire by time.
            for (Map.Entry<String, Jwt> entry : map.entrySet()) {
                Jwt value = entry.getValue();
                if(value != null) {
                    OAuth2TokenValidatorResult result = jwtValidator.validate(value);
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
            for (Map.Entry<String, Jwt> entry : cache.map.entrySet()) {
                // bail out as soon as capacity is reached instead of checking size per-entry
                if (map.size() >= maxCacheSize) {
                    return;
                }
                Jwt value = entry.getValue();
                if (value == null) {
                    continue;
                }
                String kid = (String) value.getHeaders().get("kid");
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

    // whether to keep serving cached/validated JWTs while the JWK set fails to refresh
    // (a "refresh outage"), and if so, for how long (millis) to keep tolerating a
    // continuing outage before flushing the cache; -1 tolerates outages indefinitely
    protected final boolean outageCacheEnabled;
    protected final long outageCacheTimeToLive;

    // the time of the last successful refresh (RefreshCompletedEvent), used as the anchor
    // point for measuring how long an ongoing refresh outage has lasted; initialized at
    // construction time since that is when the initial cache/JWK set is considered fresh
    protected volatile long lastRefreshCompletedAt = System.currentTimeMillis();

    // whether the 50%/75%-of-time-to-live warnings have already been logged for the
    // current outage, reset whenever the outage clock itself resets (successful refresh)
    protected volatile boolean outageHalfTimeWarningLogged = false;
    protected volatile boolean outageThreeQuarterTimeWarningLogged = false;

    protected volatile Cache cache;

    public DecodedJwtCacheJwtDecoder(JwtDecoder jwtValidatingDecoder, OAuth2TokenValidator<Jwt> jwtValidators, long cleanupIntervalMillis, int maxCacheSize) {
        // preserve historical behaviour: tolerate refresh outages indefinitely
        this(jwtValidatingDecoder, jwtValidators, cleanupIntervalMillis, maxCacheSize, true, -1L);
    }

    public DecodedJwtCacheJwtDecoder(JwtDecoder jwtValidatingDecoder, OAuth2TokenValidator<Jwt> jwtValidators, long cleanupIntervalMillis, int maxCacheSize,
                                      boolean outageCacheEnabled, long outageCacheTimeToLiveMillis) {
        this.jwtValidatingDecoder = jwtValidatingDecoder;
        this.jwtValidator = jwtValidators;
        this.cleanupInterval = cleanupIntervalMillis;
        this.maxCacheSize = maxCacheSize;
        this.outageCacheEnabled = outageCacheEnabled;
        this.outageCacheTimeToLive = outageCacheTimeToLiveMillis;

        cache = new Cache(DecodedJwtCacheJWKRepresentations.empty(), 0, jwtValidator);
    }

    public synchronized void scheduleCleanup() {
        if (cleanupInterval <= 0) {
            return;
        }
        if (scheduledExecutorService == null) {
            scheduledExecutorService = createDefaultScheduledExecutorService();
        }
        scheduledExecutorService.scheduleWithFixedDelay(this::cleanup,
                cleanupInterval, cleanupInterval, TimeUnit.MILLISECONDS);
    }

    public void cleanup() {
        if(!cache.isEmpty()) {
            try {
                // avoid memory leaks due to stagnant JWTs
                int cleaned = cache.cleanInvalidJwts();
                if(cleaned > 0) {
                    if (LOGGER.isDebugEnabled()) LOGGER.debug("Cleaned {} invalid JWTs from cache, now have {}", cleaned, cache.map.size());
                }
            } catch (Throwable e) {
                // ignore, will be handled by regular flow
                LOGGER.warn("Problem cleaning cache", e);
            }
        }
    }

    @Override
    public Jwt decode(String token) throws JwtException {

        Cache c = this.cache; // defensive copy

        Jwt cachedJwt = c.get(token);
        if (cachedJwt != null) {
            // we have a cache hit, is it still valid?
            return validateJwt(cachedJwt, c);
        }

        Jwt jwt = jwtValidatingDecoder.decode(token); // also validates
        c.add(token, jwt); // only adds if the keyid is known, otherwise ignored

        // implementation note: if the first JWT also refreshes that JWKs, it will not be cached itself
        // since that will create a new cache instance (which is not the same as the local copy)

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
        for (OAuth2Error oAuth2Error : errors) {
            if (StringUtils.hasLength(oAuth2Error.getDescription())) {
                return String.format(DECODING_ERROR_MESSAGE_TEMPLATE, oAuth2Error.getDescription());
            }
        }
        return "Unable to validate Jwt";
    }

    // clears tokens, not key ids
    public void clear() {
        cache.clear();
    }

    @Override
    public void notify(Event event) {
        if(event instanceof CachingJWKSetSource.RefreshInitiatedEvent<?>) {
            // do nothing
        } else if(event instanceof CachingJWKSetSource.RefreshCompletedEvent<?>) {
            CachingJWKSetSource.RefreshCompletedEvent refreshCompletedEvent = (CachingJWKSetSource.RefreshCompletedEvent) event;

            // refresh succeeded; any ongoing outage is over, and this is the new anchor
            // point for measuring the duration of a future outage
            lastRefreshCompletedAt = System.currentTimeMillis();
            outageHalfTimeWarningLogged = false;
            outageThreeQuarterTimeWarningLogged = false;

            Cache cache = this.cache; // defensive copy
            DecodedJwtCacheJWKRepresentations keyRepresentations = DecodedJwtCacheJWKRepresentations.of(refreshCompletedEvent.getJWKSet());

            // compare the full JWK representation for each kid, not just key id or
            // RFC 7638 thumbprint, so metadata changes affecting key selection also
            // invalidate previously cached JWTs.
            if(cache.hasSameKeys(keyRepresentations)) {
                // do nothing
            } else {
                // keys were added, removed, or changed since the previous refresh; work
                // out which key ids are positively confirmed unchanged (a safe whitelist),
                // so only cached JWTs signed by those keys are migrated - everything else
                // is dropped by default rather than only excluded if provably changed
                Set<String> keyIdsToKeep = keyRepresentations.unchangedKeyIds(cache.keyRepresentations);

                // create a new cache
                Cache nextCache = new Cache(keyRepresentations, maxCacheSize, jwtValidator);
                // copy still-valid JWTs from the old cache to the new cache
                nextCache.add(cache, keyIdsToKeep);
                this.cache = nextCache;
            }
        } else if(event instanceof CachingJWKSetSource.UnableToRefreshEvent<?>) {
            handleRefreshOutage();
        } else if(event instanceof CachingJWKSetSource.RefreshTimedOutEvent<?>) {
            handleRefreshOutage();
        }
    }

    /**
     * Called whenever the JWK set fails to refresh (or times out doing so). Depending on
     * {@link #outageCacheEnabled}/{@link #outageCacheTimeToLive}, the cache of previously
     * validated JWTs is either kept as-is (tolerating the outage), or flushed - either
     * immediately (outage cache disabled) or once the outage has lasted too long -
     * forcing JWTs to be re-verified rather than trusted indefinitely against an
     * increasingly stale local cache. The outage duration is measured relative to the
     * last successful refresh ({@link #lastRefreshCompletedAt}), not relative to the
     * first observed failure, so it also accounts for any delay between the last known
     * good state and the first failure being noticed. Once the outage has lasted 50%,
     * and again at 75%, of the configured time to live, a warning is logged noting how
     * much time is left before the cache is flushed.
     */
    protected void handleRefreshOutage() {
        if (!outageCacheEnabled) {
            cache.clear();
            return;
        }
        if (outageCacheTimeToLive < 0) {
            // tolerate refresh outages indefinitely; there is no bound to warn about
            return;
        }

        long now = System.currentTimeMillis();
        long elapsed = now - lastRefreshCompletedAt;

        if (elapsed >= outageCacheTimeToLive) {
            // the outage has lasted too long to keep trusting the cache
            cache.clear();
            return;
        }

        long remaining = outageCacheTimeToLive - elapsed;
        if (elapsed >= outageCacheTimeToLive / 2 && !outageHalfTimeWarningLogged) {
            outageHalfTimeWarningLogged = true;
            LOGGER.warn("Refresh outage has lasted for 50% of the configured outage cache time to live ({} ms); {} ms left before the decoded JWT cache is flushed", outageCacheTimeToLive, remaining);
        }
        if (elapsed >= (outageCacheTimeToLive * 3) / 4 && !outageThreeQuarterTimeWarningLogged) {
            outageThreeQuarterTimeWarningLogged = true;
            LOGGER.error("Refresh outage has lasted for 75% of the configured outage cache time to live ({} ms); {} ms left before the decoded JWT cache is flushed", outageCacheTimeToLive, remaining);
        }
    }

    public void close() {
        ScheduledExecutorService executor = scheduledExecutorService; // defensive copy
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    public int getSize() {
        return cache.size();
    }
}
