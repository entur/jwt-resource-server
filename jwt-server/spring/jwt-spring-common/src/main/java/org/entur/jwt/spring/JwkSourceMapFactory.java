package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.source.JWKSetBasedJWKSource;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import org.entur.jwt.spring.actuate.DefaultJwksHealthIndicator;
import org.entur.jwt.spring.actuate.JwkSetSourceEventListener;
import org.entur.jwt.spring.actuate.ListEventListener;
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
        Map<String, ListEventListener> jwkEventListeners = new HashMap<>();

        JwkCacheProperties cache = jwkConfiguration.getCache();
        boolean caching = cache != null && cache.isEnabled();

        JwkRateLimitProperties rateLimiting = jwkConfiguration.getRateLimit();
        boolean rateLimited = rateLimiting != null && rateLimiting.isEnabled();
        if (rateLimited && !caching) {
            // rate limiting (of cache refreshes) requires caching
            if(LOGGER.isWarnEnabled()) LOGGER.warn("JWK rate limiting requires caching, so it is disabled since entur.jwt.jwk.cache.enabled=false. Set entur.jwt.jwk.rate-limit.enabled=false to remove this warning.");
            rateLimited = false;
        }

        int millisecondsPerToken = 0;
        if (rateLimited) {
            double tokensPerSecond = rateLimiting.getRefillRate();

            double secondsPerToken = 1d / tokensPerSecond;

            millisecondsPerToken = (int) (secondsPerToken * 1000); // note quantization, ms precision is sufficient

            if (cache.getTimeToLive() * 1000 <= millisecondsPerToken) {
                throw new IllegalStateException("JWK cache time-to-live must be greater than the rate limit interval: entur.jwt.jwk.cache.time-to-live is " + cache.getTimeToLive() + " seconds, "
                        + "while entur.jwt.jwk.rate-limit.refill-rate " + tokensPerSecond + " per second gives an interval of " + (millisecondsPerToken / 1000d) + " seconds. "
                        + "Increase entur.jwt.jwk.cache.time-to-live or entur.jwt.jwk.rate-limit.refill-rate, or set entur.jwt.jwk.rate-limit.enabled=false.");
            }
        }

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

            ListEventListener eventListener = new ListEventListener();
            eventListener.addEventListener(new JwkSetSourceEventListener(entry.getKey()));

            int connectTimeout = jwkConfiguration.getConnectTimeout();
            int readTimeout = jwkConfiguration.getReadTimeout();

            DefaultResourceRetriever retriever = new DefaultResourceRetriever(connectTimeout * 1000, readTimeout * 1000, 51200);

            JWKSourceBuilder<SecurityContext> builder = JWKSourceBuilder.create(url, retriever);

            if (rateLimited) {
                builder.rateLimited(millisecondsPerToken, eventListener);
            } else {
                builder.rateLimited(false);
            }

            if (caching) {
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
            jwkEventListeners.put(tenantConfiguration.getIssuer(), eventListener);
        }

        return new JwkSourceMap(jwkSources, jwkEventListeners);
    }


}