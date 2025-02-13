package org.entur.jwt.client.grpc;

import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantLock;

/**
 *
 * Handle reactive refresh of JWT tokens upon UNAUTHENTICATED grpc status from downstream services,
 * which indicate that the JWK have been rotated (and the old keys were blacklisted).<br><br>
 *
 * There is however other reasons (i.e. bugs) to return UNAUTHENTICATED, so throttle how often the client
 * refreshes the access-token.
 * <br><br>
 * Refresh is performed in the background; there is no "rescue" for the failed call, i.e. key rotations with key
 * revocation is such a seldom event that some noise is acceptable.
 */

public class RatelimitedJwkRotationAccessTokenRecoveryHandler implements JwkRotationAccessTokenRecoveryHandler {

    private static final Logger log = LoggerFactory.getLogger(RatelimitedJwkRotationAccessTokenRecoveryHandler.class);

    private final ExecutorService executorService;

    private ReentrantLock reentrantLock = new ReentrantLock();

    private final long minTimeInterval;
    private long nextOpeningTime = -1L;
    private int counter = 0;

    public RatelimitedJwkRotationAccessTokenRecoveryHandler(final long minTimeInterval) {
        this.minTimeInterval = minTimeInterval;

        this.executorService = Executors.newSingleThreadExecutor();
    }

    @Override
    public void handle(AccessTokenProvider accessTokenProvider, String authorizationHeader, long currentTime) {
        try {
            if(reentrantLock.tryLock()) {
                try {
                    queueRefresh(accessTokenProvider, authorizationHeader, currentTime);
                } finally {
                    reentrantLock.unlock();
                }
            } else {
                // another thread is doing this
            }
        } catch(Throwable e) {
            log.warn("Problem queuing refreshing access-token in background", e);
        }
    }

    private void queueRefresh(AccessTokenProvider accessTokenProvider, String header, long currentTime) throws AccessTokenException {
        executorService.submit(() -> {
            try {
                AccessToken currentAccessToken = accessTokenProvider.getAccessToken(false);
                if(header.endsWith(currentAccessToken.getValue())) {
                    if (refresh(accessTokenProvider, currentTime)) {
                        log.info("Force refreshed access-token");
                    } else {
                        log.info("Not refreshing access-token due to rate limiting");
                    }
                } else {
                    // access-token already refreshed
                }
            } catch(Throwable e) {
                log.warn("Problem force refresh access-token", e);
            }
        });
    }

    private boolean refresh(AccessTokenProvider accessTokenProvider, long currentTime) throws AccessTokenException {
        if (!isRateLimited(currentTime)) {
            accessTokenProvider.getAccessToken(true);
            return true;
        }
        return false;
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
        executorService.close();
    }

    public ExecutorService getExecutorService() {
        return executorService;
    }
}
