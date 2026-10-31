package org.entur.jwt.client;

/**
 * Token unavailability with a fixed, JVM-local monotonic retry deadline.
 * Re-throwing this exception does not restart the wait.
 */
public class AccessTokenRetryAfterException extends AccessTokenUnavailableException {

    private static final long serialVersionUID = 1L;

    /** Fixed deadline in the process-local nanoTime domain. */
    private final long retryAfterDeadlineNanos;
    /** Whether the failure followed a token request rather than admission rejection. */
    private final boolean requestAttempted;

    /**
     * Create a token failure or admission rejection with a fixed retry deadline.
     *
     * @param message failure description
     * @param cause original failure, or null for a rejected request
     * @param retryAfterDeadlineNanos deadline in the {@link System#nanoTime()} time domain
     * @param requestAttempted whether this invocation attempted a token request
     */
    public AccessTokenRetryAfterException(String message, Throwable cause, long retryAfterDeadlineNanos, boolean requestAttempted) {
        super(message, cause);
        this.retryAfterDeadlineNanos = retryAfterDeadlineNanos;
        this.requestAttempted = requestAttempted;
    }

    /**
     * Return the deadline without recalculating or extending it.
     *
     * @return fixed monotonic deadline; subtract the current nanoTime to obtain the remaining delay
     */
    public long getRetryAfterDeadlineNanos() {
        return retryAfterDeadlineNanos;
    }

    /**
     * Distinguish a failed request from rejection by an existing deadline.
     *
     * @return false when an existing deadline rejected the invocation before a token request
     */
    public boolean isRequestAttempted() {
        return requestAttempted;
    }
}
