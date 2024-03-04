package org.entur.jwt.client.spring.actuate;

import org.entur.jwt.client.AccessTokenHealth;
import org.entur.jwt.client.AccessTokenHealthProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * 
 * Health indicator that injects itself into the corresponding health endpoint.
 * 
 * Assuming we're checking for readiness.
 * 
 */

public class AccessTokenProviderHealthIndicator extends AbstractJwtHealthIndicator implements Closeable {

    protected static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenProviderHealthIndicator.class);

    private static class JwtHealthIndicator {

        private final AccessTokenHealthProvider provider;
        private final String name;

        public JwtHealthIndicator(String name, AccessTokenHealthProvider provider) {
            this.name = name;
            this.provider = provider;
        }

        public AccessTokenHealth refreshHealth() {
            long time = System.currentTimeMillis();

            try {
                // note: the cache will refresh if an existing value is expired or bad
                return provider.getHealth(true);
            } catch (Exception e) {
                LOGGER.warn("Unable to refresh " + name + " JWT health status", e);
                return new AccessTokenHealth(time, false);
            }
        }

        public boolean isHealthy() {
            // do not refresh health, get whatever it is currently
            try {
                AccessTokenHealth health = provider.getHealth(false);

                return health != null && health.isSuccess();
            } catch (Exception e) {
                // should never happen
                LOGGER.warn("Unable to get " + name + " JWT health status", e);
                return false;
            }
        }

        public String getName() {
            return name;
        }
    }


    private ExecutorService executor;
    private List<JwtHealthIndicator> healthIndicators = new ArrayList<>();

    private volatile CountDownLatch countDownLatch = new CountDownLatch(0);

    public AccessTokenProviderHealthIndicator(ExecutorService executor, String name) {
        super(name);
        this.executor = executor;
    }

    public void addHealthIndicators(String name, AccessTokenHealthProvider provider) {
        this.healthIndicators.add(new JwtHealthIndicator(name, provider));
    }

    @Override
    public void close() {
        this.executor.shutdown();
    }

    @Override
    protected AccessTokenHealth refreshHealth() {
        long time = System.currentTimeMillis();

        List<JwtHealthIndicator> unhealthy = new ArrayList<>(healthIndicators.size());
        List<JwtHealthIndicator> healthy = new ArrayList<>(healthIndicators.size());

        for (JwtHealthIndicator healthIndicator : healthIndicators) {
            if(healthIndicator.isHealthy()) {
                healthy.add(healthIndicator);
            } else {
                unhealthy.add(healthIndicator);
            }
        }

        if(unhealthy.isEmpty()) {
            return new AccessTokenHealth(time, true);
        }

        // attempt to recover the unhealthy status in the background, but only if work is not already in progress
        synchronized (this) {
            if(isIdle()) {
                refreshHealth(healthy, unhealthy, time);
            } else {
                LOGGER.info("Previous health refresh is still in progress ({} outstanding)", countDownLatch.getCount());
            }
        }

        return new AccessTokenHealth(time, false);
    }

    private void refreshHealth(List<JwtHealthIndicator> healthy, List<JwtHealthIndicator> unhealthy, long time) {
        countDownLatch = new CountDownLatch(unhealthy.size());

        if(healthIndicators.size() > 1) {
            // print summary
            StringBuilder builder = new StringBuilder();
            builder.append("Refreshing ");
            builder.append(unhealthy.size());
            builder.append(" unhealthy JWT sources (");
            for (JwtHealthIndicator defaultJwksHealthIndicator : unhealthy) {
                builder.append(defaultJwksHealthIndicator.getName());
                builder.append(", ");
            }
            builder.setLength(builder.length() - 2);
            builder.append(") in the background.");
            if (!healthy.isEmpty()) {
                builder.append(" The other ");
                builder.append(healthy.size());
                builder.append(" JWT sources (");
                for (JwtHealthIndicator defaultJwksHealthIndicator : healthy) {
                    builder.append(defaultJwksHealthIndicator.getName());
                    builder.append(", ");
                }
                builder.setLength(builder.length() - 2);
                builder.append(") are healthy.");
            }

            LOGGER.info(builder.toString());
        }
        for (JwtHealthIndicator indicator : unhealthy) {
            executor.submit(() -> {
                try {
                    refresh(indicator, time);
                } finally {
                    countDownLatch.countDown();
                }
            });
        }
    }

    private static boolean refresh(JwtHealthIndicator indicator, long time) {
        // so either no status or bad status
        // attempt to refresh the cache
        LOGGER.info("Refresh {} JWT health", indicator.getName());

        AccessTokenHealth health = indicator.refreshHealth();
        if(health != null && health.isSuccess()) {
            LOGGER.info("{} JWT is now healthy (in {}ms)", indicator.getName(), System.currentTimeMillis() - time);

            return true;
        } else {
            LOGGER.info("{} JWT remains unhealthy (in {}ms)", indicator.getName(), System.currentTimeMillis() - time);

            return false;
        }
    }

    public boolean isIdle() {
        synchronized (this) {
            return countDownLatch.getCount() == 0L;
        }
    }

    // for testing
    public void setExecutor(ExecutorService executor) {
        this.executor = executor;
    }
}