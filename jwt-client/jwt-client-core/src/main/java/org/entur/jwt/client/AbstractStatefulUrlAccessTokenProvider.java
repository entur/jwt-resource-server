package org.entur.jwt.client;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * {@linkplain AccessTokenProvider} which handles refresh tokens.
 *
 */

public abstract class AbstractStatefulUrlAccessTokenProvider extends AbstractUrlAccessTokenProvider {

    protected static final String KEY_REFRESH_TOKEN = "refresh_token";

    protected final URL revokeUrl;
    protected final URL refreshUrl;

    protected volatile RefreshToken refreshToken;

    public AbstractStatefulUrlAccessTokenProvider(URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers, URL refreshUrl, URL revokeUrl) {
        super(issueUrl, parameters, headers);
        this.refreshUrl = refreshUrl;
        this.revokeUrl = revokeUrl;
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

    public AccessToken getAccessToken(long time) throws AccessTokenException {
        // note: force refresh is not relevant for whether to use refresh-token or not
        ClientCredentialsResponse token;

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
