package org.entur.jwt.spring.cache;

import org.entur.jwt.spring.properties.JwtProperties;
import org.entur.jwt.spring.properties.jwk.JwkCacheProperties;
import org.entur.jwt.spring.properties.jwk.JwtTenantProperties;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class DecodedJwtCacheConfigurationReader {

    public static Set<String> convert(JwtProperties jwt) {
        JwkCacheProperties cache = jwt.getJwk().getCache();
        boolean decodedJwtCache = cache.isEnabled() && cache.getPreemptive().isEnabled() && cache.getPreemptive().getEager().isEnabled();

        Set<String> decodedJwtCacheIssuers;
        if(decodedJwtCache) {
            decodedJwtCacheIssuers = new HashSet<>();
            for (Map.Entry<String, JwtTenantProperties> entry : jwt.getTenants().entrySet()) {
                JwtTenantProperties value = entry.getValue();
                if(value.isEnabled() && value.getDecoderCache().isEnabled()) {
                    decodedJwtCacheIssuers.add(entry.getKey());
                }
            }
        } else {
            decodedJwtCacheIssuers = Collections.emptySet();
        }
        return decodedJwtCacheIssuers;
    }
}
