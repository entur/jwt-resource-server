package org.entur.jwt.client;

/**
 * This provider implements a workaround for transient network problems. <br>
 * <br>
 * It retries getting the {@linkplain AccessToken} once after an
 * {@linkplain AccessTokenUnavailableException}, except that
 * {@linkplain AccessTokenRetryAfterException} is always propagated unchanged.
 */

public class RetryingAccessTokenProvider extends BaseAccessTokenProvider {

    public RetryingAccessTokenProvider(AccessTokenProvider provider) {
        super(provider);
    }

    @Override
    public AccessToken getAccessToken(boolean forceRefresh) throws AccessTokenException {
        try {
            return provider.getAccessToken(forceRefresh);
        } catch (AccessTokenRetryAfterException e) {
            throw e;
        } catch (AccessTokenUnavailableException e) {
            // assume transient network issue, retry once
            return provider.getAccessToken(forceRefresh);
        }
    }

}
