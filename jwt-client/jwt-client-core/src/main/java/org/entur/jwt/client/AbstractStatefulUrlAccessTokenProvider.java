package org.entur.jwt.client;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@linkplain AccessTokenProvider} which handles refresh tokens.
 *
 */

public abstract class AbstractStatefulUrlAccessTokenProvider<T> extends AbstractUrlAccessTokenProvider<T> {

    protected static final Logger logger = LoggerFactory.getLogger(AbstractStatefulUrlAccessTokenProvider.class);

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

    protected void close(long time) {
        RefreshToken threadSafeRefreshToken = this.refreshToken; // defensive copy
        if (threadSafeRefreshToken != null && threadSafeRefreshToken.isValid(time)) {
            this.refreshToken = null;

            StringBuilder builder = new StringBuilder();

            builder.append(KEY_REFRESH_TOKEN);
            builder.append('=');
            builder.append(encode(threadSafeRefreshToken.getValue()));

            byte[] revokeBody = builder.toString().getBytes(StandardCharsets.UTF_8);

            try {
                T request = request(revokeUrl, revokeBody, Collections.emptyMap());
                int responseStatusCode = getResponseStatusCode(request);
                if (getResponseStatusCode(request) != 200) {
                    logger.info("Unexpected response code {} when revoking refresh token", responseStatusCode);
                }
            } catch (IOException e) {
                logger.warn("Unable to revoke token", e);
            }
        }
    }

    protected ClientCredentialsResponse getToken(RefreshToken response) throws AccessTokenException {
        StringBuilder builder = new StringBuilder();

        builder.append(KEY_GRANT_TYPE);
        builder.append('=');
        builder.append(KEY_REFRESH_TOKEN);
        builder.append('&');
        builder.append(KEY_REFRESH_TOKEN);
        builder.append('=');
        builder.append(encode(response.getValue()));

        byte[] refreshBody = builder.toString().getBytes(StandardCharsets.UTF_8);

        try {
            T request = request(refreshUrl, refreshBody, Collections.emptyMap());

            int responseCode = getResponseStatusCode(request);
            if (responseCode != 200) {
                logger.info("Got unexpected response code {} when trying to refresh token at {}", responseCode, refreshUrl);
                if (responseCode == 503) { // service unavailable
                    throw new AccessTokenUnavailableException("Authorization server responded with HTTP code 503 - service unavailable. " + printHeadersIfPresent(request, "Retry-After"));
                } else if (responseCode == 429) { // too many calls
                    // see for example https://auth0.com/docs/policies/rate-limits
                    throw new AccessTokenUnavailableException("Authorization server responded with HTTP code 429 - too many requests. " + printHeadersIfPresent(request, "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"));
                }

                throw new RefreshTokenException("Authorization server responded with HTTP unexpected response code " + responseCode);
            }
            try (InputStream inputStream = getResponseContent(request)) {
                ClientCredentialsResponse clientCredentialsResponse = reader.readValue(inputStream);
                validate(clientCredentialsResponse);
                return clientCredentialsResponse;
            }
        } catch (IOException e) {
            throw new AccessTokenUnavailableException(e);
        }
    }

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
}
