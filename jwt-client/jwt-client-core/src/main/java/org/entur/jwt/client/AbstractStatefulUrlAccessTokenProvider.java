package org.entur.jwt.client;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * {@linkplain AccessTokenProvider} which handles refresh tokens.
 *
 */

public abstract class AbstractStatefulUrlAccessTokenProvider extends AbstractUrlAccessTokenProvider {

    protected static final String KEY_REFRESH_TOKEN = "refresh_token";

    // Default used by the deprecated constructor which does not take an explicit call timeout.
    public static final long DEFAULT_CALL_TIMEOUT_MILLIS = TimeUnit.SECONDS.toMillis(30);

    protected final URL revokeUrl;
    protected final URL refreshUrl;

    protected volatile RefreshToken refreshToken;

    // The maximum time to wait to acquire refreshLock in getAccessToken(long), in milliseconds.
    private final long callTimeoutMillis;

    // strictly not necessary if a wrapping provider has its own lock
    private final ReentrantLock refreshLock = new ReentrantLock();

    /**
     * @deprecated use {@link #AbstractStatefulUrlAccessTokenProvider(URL, Map, Map, URL, URL, long)} instead,
     * explicitly specifying the call timeout.
     */
    @Deprecated
    public AbstractStatefulUrlAccessTokenProvider(URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers, URL refreshUrl, URL revokeUrl) {
        this(issueUrl, parameters, headers, refreshUrl, revokeUrl, DEFAULT_CALL_TIMEOUT_MILLIS);
    }

    /**
     * @param callTimeoutMillis the maximum time to wait to acquire the internal refresh lock in
     *                          {@linkplain #getAccessToken(long)}, in milliseconds. Should not exceed
     *                          the time a single token / refresh-token HTTP call is allowed to take.
     */
    public AbstractStatefulUrlAccessTokenProvider(URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers, URL refreshUrl, URL revokeUrl, long callTimeoutMillis) {
        super(issueUrl, parameters, headers);

        checkArgument(callTimeoutMillis > 0, "Invalid call timeout value '" + callTimeoutMillis + "'. Must be a positive value.");

        this.refreshUrl = refreshUrl;
        this.revokeUrl = revokeUrl;
        this.callTimeoutMillis = callTimeoutMillis;
    }

    @Override
    public void close() {
        close(System.currentTimeMillis());
    }

    protected abstract void close(long time);

    protected byte[] createRevokeBody(RefreshToken threadSafeRefreshToken) {
        StringBuilder builder = new StringBuilder();

        builder.append(KEY_REFRESH_TOKEN);
        builder.append('=');
        builder.append(encode(threadSafeRefreshToken.getValue()));

        return builder.toString().getBytes(StandardCharsets.UTF_8);
    }

    protected byte[] createRefreshBody(RefreshToken response) {
        StringBuilder builder = new StringBuilder();

        builder.append(KEY_GRANT_TYPE);
        builder.append('=');
        builder.append(KEY_REFRESH_TOKEN);
        builder.append('&');
        builder.append(KEY_REFRESH_TOKEN);
        builder.append('=');
        builder.append(encode(response.getValue()));

        return builder.toString().getBytes(StandardCharsets.UTF_8);
    }

    protected abstract ClientCredentialsResponse getToken(RefreshToken response) throws AccessTokenException;

    @Override
    public AccessToken getAccessToken(boolean forceRefresh) throws AccessTokenException {
        return getAccessToken(System.currentTimeMillis());
    }

    /**
     * @return the maximum time to wait to acquire the internal refresh lock in
     * {@linkplain #getAccessToken(long)}, in milliseconds.
     */
    public long getCallTimeoutMillis() {
        return callTimeoutMillis;
    }

    public AccessToken getAccessToken(long time) throws AccessTokenException {
        // note: force refresh is not relevant for whether to use refresh-token or not
        ClientCredentialsResponse token;

        try {
            if (refreshLock.tryLock(callTimeoutMillis, TimeUnit.MILLISECONDS)) {
                try {
                    time = Math.max(time, System.currentTimeMillis());
                    RefreshToken threadSafeRefreshToken = this.refreshToken; // defensive copy
                    if (threadSafeRefreshToken != null && threadSafeRefreshToken.isValid(time)) {
                        try {
                            token = getToken(threadSafeRefreshToken);
                        } catch (RefreshTokenException e) {
                            // assume current session has been revoked or expired
                            // open a new session and forget about the old one
                            token = getToken();
                        }
                    } else {
                        token = getToken();
                    }

                    if (token.getRefreshToken() != null) {
                        long expires;

                        // refresh token expiry is a non-standard claim
                        // so in other words it will not always be present
                        if (token.getRefreshExpiresIn() != null) {
                            expires = time + token.getRefreshExpiresIn() * 1000;
                        } else {
                            expires = -1L;
                        }
                        this.refreshToken = new RefreshToken(token.getRefreshToken(), expires);
                    } else {
                        this.refreshToken = null;
                    }
                } finally {
                    refreshLock.unlock();
                }
            } else {
                throw new AccessTokenUnavailableException("Timeout while waiting to refresh access token (limit of " + callTimeoutMillis + "ms exceeded).");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // Restore interrupted state to make sonar happy

            throw new AccessTokenUnavailableException("Interrupted while waiting to refresh access token", e);
        }

        return new AccessToken(token.getAccessToken(), token.getTokenType(), time + token.getExpiresIn() * 1000);
    }

    public RefreshToken getRefreshToken() {
        return refreshToken;
    }
    
    @Override
    public boolean supportsHealth() {
        return false;
    }
}
