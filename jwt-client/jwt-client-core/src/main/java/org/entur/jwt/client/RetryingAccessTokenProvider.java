package org.entur.jwt.client;

/**
 * This provider implements a workaround for transient network problems. <br>
 * <br>
 * It retries getting the {@linkplain AccessToken} once after an
 * {@linkplain AccessTokenUnavailableException}, unless the provider or
 * exception reports an active retry deadline.
 */

public class RetryingAccessTokenProvider extends BaseAccessTokenProvider {

    public RetryingAccessTokenProvider(AccessTokenProvider provider) {
        super(provider);
    }

    @Override
    public AccessToken getAccessToken(boolean forceRefresh) throws AccessTokenException {
        try {
            return provider.getAccessToken(forceRefresh);
        } catch (AccessTokenUnavailableException e) {
            long nowNanos = nanoTime();
            Long providerRetryDeadline = provider.getRetryAfterDeadlineNanos();
            if (providerRetryDeadline != null && providerRetryDeadline - nowNanos > 0) {
                throw e;
            }

            if (e instanceof AccessTokenRetryAfterException retryAfter) {
                long exceptionRetryDeadline = retryAfter.getRetryAfterDeadlineNanos();
                if (exceptionRetryDeadline - nowNanos > 0) {
                    throw e;
                }
            }

            // assume transient network issue, retry once
            return provider.getAccessToken(forceRefresh);
        }
    }

    /**
     * Read the clock used to check retry deadlines.
     * @return current monotonic time, in nanoseconds
     */
    protected long nanoTime() {
        return System.nanoTime();
    }

}
