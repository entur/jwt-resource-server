package org.entur.jwt.spring.cache;

import org.entur.jwt.spring.properties.JwtProperties;
import org.entur.jwt.spring.properties.jwk.JwkCacheProperties;
import org.entur.jwt.spring.properties.jwk.JwtDecoderCacheProperties;
import org.entur.jwt.spring.properties.jwk.JwtTenantProperties;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class DecodedJwtCacheConfigurationReader {

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
            decodedJwtCacheIssuers = Collections.emptyMap();
        }
        return decodedJwtCacheIssuers;
    }
}
