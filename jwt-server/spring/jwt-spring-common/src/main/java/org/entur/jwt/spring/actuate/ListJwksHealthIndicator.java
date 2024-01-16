package org.entur.jwt.spring.actuate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

public class ListJwksHealthIndicator extends AbstractJwksHealthIndicator implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(ListJwksHealthIndicator.class);

    private final long maxDelay;

    private final ExecutorService executorService;
    private List<DefaultJwksHealthIndicator> healthIndicators = new ArrayList<>();

    public ListJwksHealthIndicator(long maxDelay, ExecutorService executorService) {
        this.maxDelay = maxDelay;
        this.executorService = executorService;
    }

    public void addHealthIndicators(DefaultJwksHealthIndicator healthIndicator) {
        this.healthIndicators.add(healthIndicator);
    }

    @Override
    public void close() throws IOException {
        this.executorService.shutdown();
    }

    @Override
    protected JwksHealth getJwksHealth() {
        long time = System.currentTimeMillis();

        List<DefaultJwksHealthIndicator> unhealthy = new ArrayList<>(healthIndicators.size());

        for (DefaultJwksHealthIndicator healthIndicator : healthIndicators) {
            if(!healthIndicator.isJwksHealtyReport()) {
                unhealthy.add(healthIndicator);
            }
        }

        if(unhealthy.isEmpty()) {
            return new JwksHealth(time, true);
        }

        if(unhealthy.size() == 1) {
            DefaultJwksHealthIndicator indicator = unhealthy.get(0);

            // so either not status or bad status
            // attempt to refresh the cache
            if(indicator.refreshJwksHealth(time)) {
                return new JwksHealth(time, true);
            }
            return new JwksHealth(time, false);
        }

        // refresh multiple sources, wrap in completion service to them all at once
        ExecutorCompletionService completionService = new ExecutorCompletionService(executorService);

        List<Future<Boolean>> workerList = new ArrayList<>(unhealthy.size());

        for (DefaultJwksHealthIndicator defaultJwksHealthIndicator : unhealthy) {
            Future<Boolean> future = completionService.submit(() -> defaultJwksHealthIndicator.refreshJwksHealth(time));

            workerList.add(future);
        }

        Future<?> timeout = executorService.submit(() -> {
            try {
                Thread.sleep(maxDelay);

                for (Future<Boolean> worker : workerList) {
                    worker.cancel(true);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Throwable e) {
                // ignore
            }
        });

        try {
            // get the results as they come in
            for (int i = 0; i < workerList.size(); i++) {
                // if one fails, status is bad
                // TODO add some kind of health policy
                try {
                    Future<Boolean> take = completionService.take();

                    Boolean status = take.get();
                    if (status != null && status) {
                        continue;
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (Exception e) {
                    // ignore
                    LOGGER.info("Problem getting health info", e);
                }
                return new JwksHealth(time, false);
            }
            return new JwksHealth(time, true);
        } finally {
            timeout.cancel(true);

            for (Future worker : workerList) {
                worker.cancel(true);
            }
        }
    }

}
