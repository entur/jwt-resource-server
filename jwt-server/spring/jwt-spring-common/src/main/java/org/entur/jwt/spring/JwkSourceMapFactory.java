package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.source.JWKSetBasedJWKSource;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import org.entur.jwt.spring.actuate.DefaultJwksHealthIndicator;
import org.entur.jwt.spring.actuate.JwkSetSourceEventListener;
import org.entur.jwt.spring.actuate.ListJwksHealthIndicator;
import org.entur.jwt.spring.properties.jwk.JwkCacheProperties;
import org.entur.jwt.spring.properties.jwk.JwkLocationProperties;
import org.entur.jwt.spring.properties.jwk.JwkOutageCacheProperties;
import org.entur.jwt.spring.properties.jwk.JwkPreemptiveCacheProperties;
import org.entur.jwt.spring.properties.jwk.JwkProperties;
import org.entur.jwt.spring.properties.jwk.JwkRateLimitProperties;
import org.entur.jwt.spring.properties.jwk.JwkRetryProperties;
import org.entur.jwt.spring.properties.jwk.JwtTenantProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class JwkSourceMapFactory<C> {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwkSourceMapFactory.class);


    public JwkSourceMap getJwkSourceMap(Map<String, JwtTenantProperties> tenants, JwkProperties jwkConfiguration, ListJwksHealthIndicator listJwksHealthIndicator) {
        Map<String, JWKSource> jwkSources = new HashMap<>();

        for (Map.Entry<String, JwtTenantProperties> entry : tenants.entrySet()) {
            JwtTenantProperties tenantConfiguration = entry.getValue();
            if (!tenantConfiguration.isEnabled()) {
                continue;
            }
            JwkLocationProperties tenantJwkConfiguration = tenantConfiguration.getJwk();
            if (tenantJwkConfiguration == null) {
                throw new IllegalStateException("Missing JWK location for " + entry.getKey());
            }
            if(LOGGER.isInfoEnabled()) LOGGER.info("Configure tenant '{}' with issuer '{}' and JWK location {}", entry.getKey(), tenantConfiguration.getIssuer(), tenantConfiguration.getJwk().getLocation());

            String location = tenantJwkConfiguration.getLocation();
            if (location == null) {
                throw new IllegalStateException("Missing JWK location for " + entry.getKey());
            }

            URL url;
            try {
                url = new URL(location);
            } catch (MalformedURLException e) {
                throw new IllegalArgumentException("Invalid location " + tenantJwkConfiguration.getLocation() + " for " + entry.getKey());
            }

            JwkSetSourceEventListener eventListener = new JwkSetSourceEventListener(entry.getKey());

            int connectTimeout = jwkConfiguration.getConnectTimeout();
            int readTimeout = jwkConfiguration.getReadTimeout();

            DefaultResourceRetriever retriever = new DefaultResourceRetriever(connectTimeout * 1000, readTimeout * 1000, 51200);

            JWKSourceBuilder<SecurityContext> builder = JWKSourceBuilder.create(url, retriever);

            JwkRateLimitProperties rateLimiting = jwkConfiguration.getRateLimit();
            if (rateLimiting != null && rateLimiting.isEnabled()) {
                double tokensPerSecond = rateLimiting.getRefillRate();

                double secondsPerToken = 1d / tokensPerSecond;

                int millisecondsPerToken = (int) (secondsPerToken * 1000); // note quantization, ms precision is sufficient

                builder.rateLimited(millisecondsPerToken, eventListener);
            } else {
                builder.rateLimited(false);
            }

            JwkCacheProperties cache = jwkConfiguration.getCache();
            if (cache != null && cache.isEnabled()) {
                builder.cache(cache.getTimeToLive() * 1000, cache.getRefreshTimeout() * 1000, eventListener);

                JwkPreemptiveCacheProperties preemptive = cache.getPreemptive();
                if (preemptive != null && preemptive.isEnabled()) {
                    builder.refreshAheadCache(preemptive.getTimeToExpires() * 1000, preemptive.getEager().isEnabled(), eventListener);
                } else {
                    builder.refreshAheadCache(false);
                }
            } else {
                builder.cache(false);
                builder.refreshAheadCache(false);
            }

            JwkRetryProperties retrying = jwkConfiguration.getRetry();
            if (retrying != null && retrying.isEnabled()) {
                builder.retrying(eventListener);
            }

            JwkOutageCacheProperties outageCache = jwkConfiguration.getOutageCache();
            if (outageCache != null && outageCache.isEnabled()) {
                builder.outageTolerant(outageCache.getTimeToLive() * 1000, eventListener);
            } else {
                builder.outageTolerant(false);
            }

            DefaultJwksHealthIndicator healthIndicator = null;
            if (listJwksHealthIndicator != null) {
                healthIndicator = new DefaultJwksHealthIndicator(entry.getKey());
                builder.healthReporting(healthIndicator);

                if(LOGGER.isDebugEnabled()) LOGGER.debug("Add health indicator for {}", entry.getKey());

                listJwksHealthIndicator.addHealthIndicators(healthIndicator);
            }

            JWKSetBasedJWKSource<SecurityContext> jwkSource = (JWKSetBasedJWKSource) builder.build();

            if (healthIndicator != null) {
                healthIndicator.setJwkSetSource(jwkSource.getJWKSetSource());
            }

            jwkSources.put(tenantConfiguration.getIssuer(), jwkSource);
        }

        return new JwkSourceMap(jwkSources);
    }


}