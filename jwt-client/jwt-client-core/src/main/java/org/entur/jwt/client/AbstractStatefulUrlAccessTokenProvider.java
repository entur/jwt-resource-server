package org.entur.jwt.client;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

/**
 * {@linkplain AccessTokenProvider} which handles refresh tokens. <br>
 * <br>
 * The refresh and revoke requests are authenticated the same way as the issue request (RFC 6749 section 6),
 * i.e. they carry the same headers (for example a basic authorization header) and the same client id and
 * secret body parameters (if any).
 */

public abstract class AbstractStatefulUrlAccessTokenProvider extends AbstractUrlAccessTokenProvider {

    protected static final String KEY_REFRESH_TOKEN = "refresh_token";
    protected static final String KEY_CLIENT_ID = "client_id";
    protected static final String KEY_CLIENT_SECRET = "client_secret";

    protected final URL revokeUrl;
    protected final URL refreshUrl;

    protected final Map<String, Object> refreshHeaders;
    protected final Map<String, Object> revokeHeaders;
    protected final Map<String, Object> clientAuthenticationParameters;

    protected volatile RefreshToken refreshToken;

    public AbstractStatefulUrlAccessTokenProvider(URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers, URL refreshUrl, URL revokeUrl) {
        super(issueUrl, parameters, headers);
        this.refreshUrl = refreshUrl;
        this.revokeUrl = revokeUrl;

        this.refreshHeaders = headers;
        this.revokeHeaders = headers;
        this.clientAuthenticationParameters = getClientAuthenticationParameters(parameters);
    }

    protected static Map<String, Object> getClientAuthenticationParameters(Map<String, Object> parameters) {
        Map<String, Object> clientAuthenticationParameters = new LinkedHashMap<>();
        for (String key : new String[]{KEY_CLIENT_ID, KEY_CLIENT_SECRET}) {
            Object value = parameters.get(key);
            if (value != null) {
                clientAuthenticationParameters.put(key, value);
            }
        }
        return clientAuthenticationParameters;
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

        appendClientAuthenticationParameters(builder);

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

        appendClientAuthenticationParameters(builder);

        return builder.toString().getBytes(StandardCharsets.UTF_8);
    }

    protected void appendClientAuthenticationParameters(StringBuilder builder) {
        for (Entry<String, Object> entry : clientAuthenticationParameters.entrySet()) {
            builder.append('&');
            builder.append(entry.getKey());
            builder.append('=');
            builder.append(encode(entry.getValue().toString()));
        }
    }

    protected abstract ClientCredentialsResponse getToken(RefreshToken response) throws AccessTokenException;

    @Override
    public AccessToken getAccessToken(boolean forceRefresh) throws AccessTokenException {
        return getAccessToken(currentTimeMillis());
    }

    public AccessToken getAccessToken(long time) throws AccessTokenException {
        // note: force refresh is not relevant for whether to use refresh-token or not
        ClientCredentialsResponse token;

        RefreshToken threadSafeRefreshToken = this.refreshToken; // defensive copy
        if (threadSafeRefreshToken != null && threadSafeRefreshToken.isValid(time)) {
            try {
                token = requestToken(() -> getToken(threadSafeRefreshToken));
            } catch (RefreshTokenException e) {
                // assume current session has been revoked or expired
                // open a new session and forget about the old one
                this.refreshToken = null;
                Long deadline = getRetryAfterDeadlineNanos();
                if (deadline != null && deadline - nanoTime() > 0) {
                    throw new AccessTokenRetryAfterException("Refresh token rejected; new session deferred until the retry deadline", e, deadline);
                }
                token = requestToken(this::getToken);
            }
        } else {
            token = requestToken(this::getToken);
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
