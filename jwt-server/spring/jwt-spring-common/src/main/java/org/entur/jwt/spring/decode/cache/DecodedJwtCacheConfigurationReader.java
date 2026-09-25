package org.entur.jwt.spring.decode.cache;

import org.entur.jwt.spring.properties.JwtProperties;
import org.entur.jwt.spring.properties.jwk.JwkCacheProperties;
import org.entur.jwt.spring.properties.jwk.JwkOutageCacheProperties;
import org.entur.jwt.spring.properties.jwk.JwtDecoderCacheOutageProperties;
import org.entur.jwt.spring.properties.jwk.JwtDecoderCacheProperties;
import org.entur.jwt.spring.properties.jwk.JwtTenantProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class DecodedJwtCacheConfigurationReader {

    private static final Logger LOGGER = LoggerFactory.getLogger(DecodedJwtCacheConfigurationReader.class);

    public static Map<String, JwtDecoderCacheProperties> getActiveJwtDecoderCacheProperties(JwtProperties jwt) {
        JwkCacheProperties cache = jwt.getJwk().getCache();
        boolean preemptiveEagerJwk = cache.isEnabled() && cache.getPreemptive().isEnabled() && cache.getPreemptive().getEager().isEnabled();

        Map<String, JwtDecoderCacheProperties> decodedJwtCacheIssuers;
        if(preemptiveEagerJwk) {
            decodedJwtCacheIssuers = new HashMap<>();
            for (Map.Entry<String, JwtTenantProperties> entry : jwt.getTenants().entrySet()) {
                JwtTenantProperties value = entry.getValue();
                if(value.isEnabled() && value.getDecoderCache().isEnabled()) {
                    decodedJwtCacheIssuers.put(value.getIssuer(), value.getDecoderCache());

                    warnIfOutageCacheDurationsMismatch(entry.getKey(), jwt.getJwk().getOutageCache(), value.getDecoderCache().getOutageCache());
                }
            }
        } else {
            decodedJwtCacheIssuers = Collections.emptyMap();
        }
        return decodedJwtCacheIssuers;
    }

    // the JWK set's own outage cache (nimbus-level, tolerates a stale remote JWK set) and
    // the decoded JWT cache's outage cache (tolerates a stale local decode cache while the
    // JWK set fails to refresh) are configured independently, but are conceptually related:
    // if both are enabled with different time-to-live durations, one of them may flush its
    // cache well before (or long after) the other, so warn about this potentially
    // unintended combination
    private static void warnIfOutageCacheDurationsMismatch(String tenant, JwkOutageCacheProperties jwkOutageCache, JwtDecoderCacheOutageProperties decoderOutageCache) {
        if (jwkOutageCache == null || decoderOutageCache == null) {
            return;
        }
        if (!jwkOutageCache.isEnabled() || !decoderOutageCache.isEnabled()) {
            return;
        }
        if (jwkOutageCache.getTimeToLive() != decoderOutageCache.getTimeToLive()) {
            LOGGER.warn("Tenant '{}' has jwk.outage-cache.time-to-live={}s and decoder-cache.outage-cache.time-to-live={}s configured with different durations; " +
                            "consider aligning them so the JWK set outage cache and the decoded JWT cache expire together during an outage",
                    tenant, jwkOutageCache.getTimeToLive(), decoderOutageCache.getTimeToLive());
        }
    }
}
