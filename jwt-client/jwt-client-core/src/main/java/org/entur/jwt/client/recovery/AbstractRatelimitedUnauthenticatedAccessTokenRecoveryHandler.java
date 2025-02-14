package org.entur.jwt.client.recovery;

import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.*;

/**
 *
 * Handle reactive recovery of JWT tokens upon UNAUTHENTICATED grpc status from downstream services.
 * Some possible reasons for UNAUTHENTICATED:<br>
 * - JWK rotation (and the old keys were nuked)<br>
 * - bugs in the downstream service <br>
 * - token misconfiguration (i.e. missing claims)<br>
 * <br>
 * Recovery is performed in the background; there is no "retry" for the failed call. Assuming
 * UNAUTHENTICATED is a seldom event, this is acceptable.
 */

public abstract class AbstractRatelimitedUnauthenticatedAccessTokenRecoveryHandler implements UnauthenticatedAccessTokenRecoveryHandler {

    private static final Logger log = LoggerFactory.getLogger(AbstractRatelimitedUnauthenticatedAccessTokenRecoveryHandler.class);

    protected final ThreadPoolExecutor executor;

    protected final long minTimeInterval;
    protected long nextOpeningTime = -1L;
    protected int counter = 0;

    public AbstractRatelimitedUnauthenticatedAccessTokenRecoveryHandler(final long minTimeInterval) {
        this.minTimeInterval = minTimeInterval;

        this.executor = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, new LinkedBlockingQueue<Runnable>(), Executors.defaultThreadFactory());
    }

    @Override
    public void handle(AccessTokenProvider accessTokenProvider, String authorizationHeader, long currentTime) {
        try {
            BlockingQueue<Runnable> queue = executor.getQueue();
            // inaccurate, but good enough for this scenario
            if(executor.getActiveCount() == 0 && queue.size() == 0) {
                queueRefresh(accessTokenProvider, authorizationHeader, currentTime);
            }
        } catch(Throwable e) {
            log.warn("Problem queuing refreshing access-token in background", e);
        }
    }

    private void queueRefresh(AccessTokenProvider accessTokenProvider, String header, long currentTime) {
        executor.submit(() -> {
            try {
                if (isRateLimited(currentTime)) {
                    log.info("Not refreshing access-token due to rate limiting");
                    return;
                }
                recover(accessTokenProvider, header);
            } catch (Throwable e) {
                log.warn("Problem refreshing access-token", e);
            }
        });
    }

    protected abstract void recover(AccessTokenProvider accessTokenProvider, String header) throws AccessTokenException;

    protected boolean isRateLimited(long currentTime) {
        boolean rateLimitHit;
        synchronized (this) {
            if (nextOpeningTime <= currentTime) {
                nextOpeningTime = currentTime + minTimeInterval;
                counter = 0;
                rateLimitHit = false;
            } else {
                rateLimitHit = counter <= 0;
                if (!rateLimitHit) {
                    counter--;
                }
            }
        }
        return rateLimitHit;
    }

    public void close() {
        executor.close();
    }

    protected ThreadPoolExecutor getExecutor() {
        return executor;
    }
}
