package org.entur.jwt.spring.decode.cache;

import org.entur.jwt.spring.properties.JwtProperties;
import org.entur.jwt.spring.properties.jwk.JwkCacheProperties;
import org.entur.jwt.spring.properties.jwk.JwtDecoderCacheProperties;
import org.entur.jwt.spring.properties.jwk.JwtTenantProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
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
                }
            }
        } else {
            // the decoder cache relies on eager background JWK refresh for cache coherence,
            // so it is not activated without it; warn so the misconfiguration is not silent
            for (String tenant : getTenantsWithDecoderCacheEnabled(jwt)) {
                LOGGER.warn("Tenant '{}' has decoder-cache.enabled=true, but the decoded JWT cache requires entur.jwt.jwk.cache.enabled, " +
                        "entur.jwt.jwk.cache.preemptive.enabled and entur.jwt.jwk.cache.preemptive.eager.enabled to all be true; the decoded JWT cache is disabled", tenant);
            }
            decodedJwtCacheIssuers = Collections.emptyMap();
        }
        return decodedJwtCacheIssuers;
    }

    /**
     * @return names of enabled tenants which have opted in to the decoded JWT cache, regardless
     * of whether the rest of the configuration allows the cache to be activated.
     */
    public static List<String> getTenantsWithDecoderCacheEnabled(JwtProperties jwt) {
        List<String> tenants = new ArrayList<>();
        for (Map.Entry<String, JwtTenantProperties> entry : jwt.getTenants().entrySet()) {
            JwtTenantProperties value = entry.getValue();
            if (value.isEnabled() && value.getDecoderCache().isEnabled()) {
                tenants.add(entry.getKey());
            }
        }
        return tenants;
    }

}
