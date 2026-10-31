package org.entur.jwt.client;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Token unavailability with a fixed, JVM-local monotonic deadline for the next attempt.
 * Callers may use the deadline to defer subsequent work; rethrowing does not restart it.
 */
public class AccessTokenRetryAfterException extends AccessTokenUnavailableException {

    private static final long serialVersionUID = 1L;

    /** Fixed deadline in the process-local nanoTime domain. */
    private final long retryAfterDeadlineNanos;

    /** Rate limit response headers, for logging. */
    private final Map<String, String> headers;

    /**
     * Create a token failure or admission rejection with a fixed retry deadline.
     *
     * @param message failure description
     * @param cause original failure, or null when none is available
     * @param retryAfterDeadlineNanos deadline in the {@link System#nanoTime()} time domain
     */
    public AccessTokenRetryAfterException(String message, Throwable cause, long retryAfterDeadlineNanos) {
        this(message, cause, retryAfterDeadlineNanos, Map.of());
    }

    /**
     * Create a token failure with a fixed retry deadline and the response headers it was derived from.
     *
     * @param message failure description
     * @param cause original failure, or null when none is available
     * @param retryAfterDeadlineNanos deadline in the {@link System#nanoTime()} time domain
     * @param headers response headers to keep as context, for logging
     */
    public AccessTokenRetryAfterException(String message, Throwable cause, long retryAfterDeadlineNanos, Map<String, String> headers) {
        super(message, cause);
        this.retryAfterDeadlineNanos = retryAfterDeadlineNanos;
        this.headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers));
    }

    /**
     * Return the rate limit response headers which accompanied the failure, such as Retry-After or X-RateLimit-Reset.
     *
     * @return unmodifiable headers by name, empty if there are none
     */
    public Map<String, String> getHeaders() {
        return headers;
    }

    /**
     * Return the deadline without recalculating or extending it.
     *
     * @return fixed monotonic deadline; subtract the current nanoTime to obtain the remaining delay
     */
    public long getRetryAfterDeadlineNanos() {
        return retryAfterDeadlineNanos;
    }

}
