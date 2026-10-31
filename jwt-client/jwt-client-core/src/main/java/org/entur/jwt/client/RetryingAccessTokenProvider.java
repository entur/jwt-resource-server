package org.entur.jwt.client;

/**
 * This provider implements a workaround for transient network problems. <br>
 * <br>
 * It retries getting the {@linkplain AccessToken} if the wrapped provider
 * throws a {@linkplain AccessTokenUnavailableException}.
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
            long now = nanoTime();
            Long deadline = provider.getRetryAfterDeadlineNanos();
            if ((deadline != null && deadline - now > 0)
                    || (e instanceof AccessTokenRetryAfterException retryAfter && retryAfter.getRetryAfterDeadlineNanos() - now > 0)) {
                throw e;
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
