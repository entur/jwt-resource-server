package org.entur.jwt.spring.actuate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

public class ListJwksHealthIndicator extends AbstractJwksHealthIndicator implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(ListJwksHealthIndicator.class);

    private final ExecutorService executorService;
    private List<DefaultJwksHealthIndicator> healthIndicators = new ArrayList<>();

    private CountDownLatch countDownLatch = new CountDownLatch(0);

    public ListJwksHealthIndicator(ExecutorService executorService, String name) {
        super(name);
        this.executorService = executorService;
    }

    public void addHealthIndicators(DefaultJwksHealthIndicator healthIndicator) {
        this.healthIndicators.add(healthIndicator);

        this.silent = healthIndicators.size() <= 1;
    }

    @Override
    public void close() {
        this.executorService.shutdown();
    }

    @Override
    protected JwksHealth getJwksHealth() {
        long time = System.currentTimeMillis();

        List<DefaultJwksHealthIndicator> unhealthy = new ArrayList<>(healthIndicators.size());
        List<DefaultJwksHealthIndicator> healthy = new ArrayList<>(healthIndicators.size());

        for (DefaultJwksHealthIndicator healthIndicator : healthIndicators) {
            if(healthIndicator.isJwksHealtyReport()) {
                healthy.add(healthIndicator);
            } else {
                unhealthy.add(healthIndicator);
            }
        }

        if(unhealthy.isEmpty()) {
            return new JwksHealth(time, true);
        }

        // attempt to recover the unhealthy status in the background, but only if work is not already in progress
        synchronized (this) {
            if(isIdle()) {
                refreshHealth(healthy, unhealthy, time);
            } else {
                LOGGER.info("Previous JWK health refresh is still in progress ({} outstanding)", countDownLatch.getCount());
            }
        }

        return new JwksHealth(time, false);
    }

    private void refreshHealth(List<DefaultJwksHealthIndicator> healthy, List<DefaultJwksHealthIndicator> unhealthy, long time) {
        countDownLatch = new CountDownLatch(unhealthy.size());

        if(healthIndicators.size() > 1) {
            // print summary
            StringBuilder builder = new StringBuilder();
            builder.append("Refreshing ");
            builder.append(unhealthy.size());
            builder.append(" unhealthy JWKs sources (");
            for (DefaultJwksHealthIndicator defaultJwksHealthIndicator : unhealthy) {
                builder.append(defaultJwksHealthIndicator.getName());
                builder.append(", ");
            }
            builder.setLength(builder.length() - 2);
            builder.append(") in the background.");
            if (!healthy.isEmpty()) {
                builder.append(" The other ");
                builder.append(healthy.size());
                builder.append(" JWKs sources (");
                for (DefaultJwksHealthIndicator defaultJwksHealthIndicator : healthy) {
                    builder.append(defaultJwksHealthIndicator.getName());
                    builder.append(", ");
                }
                builder.setLength(builder.length() - 2);
                builder.append(") are healthy.");
            }

            LOGGER.info(builder.toString());
        }
        for (DefaultJwksHealthIndicator indicator : unhealthy) {
            executorService.submit(() -> {
                try {
                    refresh(indicator, time);
                } finally {
                    countDownLatch.countDown();
                }
            });
        }
    }

    private static boolean refresh(DefaultJwksHealthIndicator indicator, long time) {
        // attempt to refresh the cache
        if(indicator.refreshJwksHealth(time)) {
            LOGGER.info("{} JWKs is now healthy (in {}ms)", indicator.getName(), System.currentTimeMillis() - time);

            return true;
        } else {
            LOGGER.info("{} JWKs remains unhealthy (in {}ms)", indicator.getName(), System.currentTimeMillis() - time);

            return false;
        }
    }

    public boolean isIdle() {
        synchronized (this) {
            return countDownLatch.getCount() == 0L;
        }
    }

}
