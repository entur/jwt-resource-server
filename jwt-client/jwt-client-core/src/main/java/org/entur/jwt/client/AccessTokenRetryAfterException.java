package org.entur.jwt.client;

/**
 * Token unavailability with a fixed, JVM-local monotonic deadline for the next attempt.
 * Callers may use the deadline to defer subsequent work; rethrowing does not restart it.
 */
public class AccessTokenRetryAfterException extends AccessTokenUnavailableException {

    private static final long serialVersionUID = 1L;

    /** Fixed deadline in the process-local nanoTime domain. */
    private final long retryAfterDeadlineNanos;

    /**
     * Create a token failure or admission rejection with a fixed retry deadline.
     *
     * @param message failure description
     * @param cause original failure, or null when none is available
     * @param retryAfterDeadlineNanos deadline in the {@link System#nanoTime()} time domain
     */
    public AccessTokenRetryAfterException(String message, Throwable cause, long retryAfterDeadlineNanos) {
        super(message, cause);
        this.retryAfterDeadlineNanos = retryAfterDeadlineNanos;
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
