package org.entur.jwt.spring.actuate;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSetCacheRefreshEvaluator;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.util.health.HealthReport;
import com.nimbusds.jose.util.health.HealthReportListener;
import com.nimbusds.jose.util.health.HealthStatus;

public class DefaultJwksHealthIndicator extends AbstractJwksHealthIndicator implements HealthReportListener {

    private JWKSetSource jwkSetSource;

    private HealthReport healthReport;

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
        } catch (Exception e) {
            return false;
        }
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
