package org.entur.jwt.spring.actuate;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSetCacheRefreshEvaluator;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.RateLimitReachedException;
import com.nimbusds.jose.util.health.HealthReport;
import com.nimbusds.jose.util.health.HealthReportListener;
import com.nimbusds.jose.util.health.HealthStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * Implementation note: This health indicator does its work in the foreground, i.e. the calling thread
 * must wait, potentially for a network call.
 *
 */

public class DefaultJwksHealthIndicator extends AbstractJwksHealthIndicator implements HealthReportListener {

    protected static final Logger logger = LoggerFactory.getLogger(DefaultJwksHealthIndicator.class);

    private JWKSetSource jwkSetSource;

    private HealthReport healthReport;

    public DefaultJwksHealthIndicator(String name) {
        super(name);
    }

    public void setJwkSetSource(JWKSetSource jwkSetSource) {
        this.jwkSetSource = jwkSetSource;
    }

    @Override
    public JwksHealth getJwksHealth() {
        long time = System.currentTimeMillis();

        if(isJwksHealtyReport()) {
            return new JwksHealth(time, true);
        }

        // so either not status or bad status
        // attempt to refresh the cache
        if(refreshJwksHealth(time)) {
            return new JwksHealth(time, true);
        }
        return new JwksHealth(time, false);
    }

    public boolean refreshJwksHealth(long time) {
        try {
            // do not force refresh an existing value;
            // the cache will refresh if an existing value is expired
            JWKSet jwkSet = jwkSetSource.getJWKSet(JWKSetCacheRefreshEvaluator.noRefresh(), time, null);

            return true;
        } catch (RateLimitReachedException e) {
            // log using a lower level
            if(logger.isInfoEnabled()) logger.info("Unable to refresh {} JWKs health status, rate limit reached.", name);
            return false;
        } catch (Exception e) {
            logger.warn("Unable to refresh " + name + " JWKs health status", e);
            return false;
        }
    }

    public boolean isHealthReport() {
        return healthReport != null;
    }

    public boolean isJwksHealtyReport() {
        // check the latest health report
        HealthReport healthReport = this.healthReport; // defensive copy
        if(healthReport != null) {
            HealthStatus healthStatus = healthReport.getHealthStatus();
            if(healthStatus == HealthStatus.HEALTHY) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void notify(HealthReport healthReport) {
        this.healthReport = healthReport;
    }

}
