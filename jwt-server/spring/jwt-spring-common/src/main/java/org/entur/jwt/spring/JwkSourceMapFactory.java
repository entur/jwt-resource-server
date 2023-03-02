package org.entur.jwt.spring;

import com.nimbusds.jose.jwk.source.JWKSource;
import org.entur.jwt.spring.auth0.properties.jwk.JwkCacheProperties;
import org.entur.jwt.spring.auth0.properties.jwk.JwkLocationProperties;
import org.entur.jwt.spring.auth0.properties.jwk.JwkOutageCacheProperties;
import org.entur.jwt.spring.auth0.properties.jwk.JwkPreemptiveCacheProperties;
import org.entur.jwt.spring.auth0.properties.jwk.JwkProperties;
import org.entur.jwt.spring.auth0.properties.jwk.JwkRateLimitProperties;
import org.entur.jwt.spring.auth0.properties.jwk.JwkRetryProperties;
import org.entur.jwt.spring.auth0.properties.jwk.JwtClaimConstraintProperties;
import org.entur.jwt.spring.auth0.properties.jwk.JwtClaimsProperties;
import org.entur.jwt.spring.auth0.properties.jwk.JwtTenantProperties;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JwkSourceMapFactory<C> {

    public JwkSourceMap getVerifier(Map<String, JwtTenantProperties> tenants, JwkProperties jwkConfiguration, JwtClaimsProperties claims) {
        Map<String, JWKSource> jwkSources = new HashMap<>();

        boolean healthIndicator = jwkConfiguration.getHealthIndicator().isEnabled();

        List<JwtClaimConstraintProperties> valueConstraints = getValueConstraints(claims);
        for (Map.Entry<String, JwtTenantProperties> entry : tenants.entrySet()) {
            JwtTenantProperties tenantConfiguration = entry.getValue();
            if(!tenantConfiguration.isEnabled()) {
                continue;
            }

            JwkLocationProperties tenantJwkConfiguration = tenantConfiguration.getJwk();
            if (tenantJwkConfiguration == null) {
                throw new IllegalStateException("Missing JWK location for " + entry.getKey());
            }
            log.info("Configure tenant '{}' with issuer '{}' and JWK location {}", entry.getKey(), tenantConfiguration.getIssuer(), tenantConfiguration.getJwk().getLocation());

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

            long connectTimeout = jwkConfiguration.getConnectTimeout();
            long readTimeout = jwkConfiguration.getReadTimeout();

            UrlJwksProvider<Jwk> urlProvider = new UrlJwksProvider<>(url, new Auth0JwkReader(), connectTimeout * 1000, readTimeout * 1000);

            Auth0JwkProviderBuilder builder = new Auth0JwkProviderBuilder(urlProvider);

            JwkRateLimitProperties rateLimiting = jwkConfiguration.getRateLimit();
            if (rateLimiting != null && rateLimiting.isEnabled()) {
                double tokensPerSecond = rateLimiting.getRefillRate();

                double secondsPerToken = 1d / tokensPerSecond;

                int millisecondsPerToken = (int)(secondsPerToken * 1000); // note quantization, ms precision is sufficient

                builder.rateLimited(rateLimiting.getBucketSize(), 1, Duration.ofMillis(millisecondsPerToken));
            } else {
                builder.rateLimited(false);
            }

            JwkCacheProperties cache = jwkConfiguration.getCache();
            if (cache != null && cache.isEnabled()) {
                builder.cached(Duration.ofSeconds(cache.getTimeToLive()), Duration.ofSeconds(cache.getRefreshTimeout()));

                JwkPreemptiveCacheProperties preemptive = cache.getPreemptive();
                if (preemptive != null && preemptive.isEnabled()) {
                    builder.preemptiveCacheRefresh(Duration.ofSeconds(preemptive.getTimeToExpires()), preemptive.getEager().isEnabled());
                } else {
                    builder.preemptiveCacheRefresh(false);
                }
            } else {
                builder.cached(false);
                builder.preemptiveCacheRefresh(false);
            }

            JwkRetryProperties retrying = jwkConfiguration.getRetry();
            builder.retrying(retrying != null && retrying.isEnabled());

            JwkOutageCacheProperties outageCache = jwkConfiguration.getOutageCache();
            if (outageCache != null && outageCache.isEnabled()) {
                builder.outageCached(Duration.ofSeconds(outageCache.getTimeToLive()));
            } else {
                builder.outageCached(false);
            }

            builder.health(healthIndicator);

            JwkProvider<Jwk> jwkProvider = builder.build();

            if (healthIndicator) {
                jwkProvider.getHealth(false); // verify that health is supported
                statusProviders.add(jwkProvider);
            }

            JwtKeyProvider keyProvider = new JwtKeyProvider(jwkProvider);

            Verification jwtBuilder = JWT.require(Algorithm.RSA256(keyProvider)).withIssuer(tenantConfiguration.getIssuer()) // strictly not necessary, but lets add it anyways
                    .acceptExpiresAt(claims.getExpiresAtLeeway()).acceptIssuedAt(claims.getIssuedAtLeeway());

            // value verification directly supported by auth0
            addValueConstraints(jwtBuilder, valueConstraints);

            CloseableJWTVerifier verifier = new AudienceJWTVerifier(jwtBuilder.build(), jwkProvider, claims.getAudiences());
            verifiers.put(tenantConfiguration.getIssuer(), verifier);
        }

        JwtVerifier<DecodedJWT> verifier;
        if (!statusProviders.isEmpty()) {
            verifier = new MultiTenantJwtVerifier(verifiers, statusProviders);
        } else {
            verifier = new MultiTenantJwtVerifier(verifiers);
        }

        List<JwtClaimConstraintProperties> dataTypeConstraints = getDataTypeConstraints(claims);
        if (!dataTypeConstraints.isEmpty()) {
            return getVerifierForDataTypes(verifier, dataTypeConstraints);
        }



        return new JwkSourceMap(jwkSources);
    }


}