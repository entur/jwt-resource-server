package org.entur.jwt.client.grpc;

import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.*;

/**
 *
 * Handle reactive refresh of JWT tokens upon UNAUTHENTICATED grpc status from downstream services,
 * which indicate that the JWK have been rotated (and the old keys were blacklisted).<br><br>
 *
 * There is however other reasons (i.e. bugs) to return UNAUTHENTICATED, so throttle how often the client
 * refreshes the access-token.
 * <br><br>
 * Refresh is performed in the background; there is no "retry" for the failed call, i.e. key rotations with key
 * revocation is such a seldom event that some noise is acceptable.
 */

public class RatelimitedJwkRotationAccessTokenRecoveryHandler implements JwkRotationAccessTokenRecoveryHandler {

    private static final Logger log = LoggerFactory.getLogger(RatelimitedJwkRotationAccessTokenRecoveryHandler.class);

    private final ThreadPoolExecutor executor;

    private final long minTimeInterval;
    private long nextOpeningTime = -1L;
    private int counter = 0;

    public RatelimitedJwkRotationAccessTokenRecoveryHandler(final long minTimeInterval) {
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
                AccessToken currentAccessToken = accessTokenProvider.getAccessToken(false);
                if (!header.endsWith(currentAccessToken.getValue())) {
                    // access-token already refreshed
                    return;
                }
                if (isRateLimited(currentTime)) {
                    log.info("Not refreshing access-token due to rate limiting");
                    return;
                }
                log.info("Force refreshed access-token");
                accessTokenProvider.getAccessToken(true);
            } catch (Throwable e) {
                log.warn("Problem refreshing access-token", e);
            }
        });
    }

    protected boolean isRateLimited(long currentTime) {
        boolean rateLimitHit;
        synchronized (this) {
            if (nextOpeningTime <= currentTime) {
                nextOpeningTime = currentTime + minTimeInterval;
                counter = 1;
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
