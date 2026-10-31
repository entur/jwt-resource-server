package org.entur.jwt.client;

import java.io.Closeable;

/**
 * Provider for {@linkplain AccessToken}. These providers should be closed, so
 * that (when refresh tokens) sessions are closed.
 * 
 */

public interface AccessTokenProvider extends Closeable, AccessTokenHealthProvider {

    AccessToken getAccessToken(boolean forceRefresh) throws AccessTokenException;

    /**
     * Expose retry backoff to decorators without starting a request.
     *
     * @return JVM-local retry deadline in the {@link System#nanoTime()} time domain,
     *         or null if none is known; a deadline may already have elapsed
     */
    default Long getRetryAfterDeadlineNanos() {
        return null;
    }

}
