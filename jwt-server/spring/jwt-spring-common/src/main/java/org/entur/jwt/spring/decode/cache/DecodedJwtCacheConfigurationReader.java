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
        List<String> tenants = new ArrayList<>();
        for (String tenant : getTenantsWithDecoderCacheEnabled(jwt)) {
            if (jwt.getTenants().get(tenant).getDecoderCache().getSize() == 0) {
                // nothing would ever be cached
                LOGGER.info("Tenant '{}' has decoder-cache.size=0, the decoded JWT cache is disabled", tenant);
                continue;
            }
            tenants.add(tenant);
        }
        if (tenants.isEmpty()) {
            return Collections.emptyMap();
        }

        JwkCacheProperties cache = jwt.getJwk().getCache();
        if (cache == null || !cache.isEnabled()) {
            // every cache hit looks up the JWT's keys in the JWK set, which without the JWK cache
            // would mean loading the JWK set; fail so the misconfiguration is not silent
            throw new IllegalStateException("decoder-cache.enabled=true for tenant(s) " + tenants + " requires entur.jwt.jwk.cache.enabled=true");
        }

        Map<String, JwtDecoderCacheProperties> decodedJwtCacheIssuers = new HashMap<>();
        for (String tenant : tenants) {
            JwtTenantProperties value = jwt.getTenants().get(tenant);
            decodedJwtCacheIssuers.put(value.getIssuer(), value.getDecoderCache());
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
