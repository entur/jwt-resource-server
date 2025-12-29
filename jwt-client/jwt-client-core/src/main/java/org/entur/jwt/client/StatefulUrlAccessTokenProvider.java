package org.entur.jwt.client;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Collections;
import java.util.Map;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectReader;
import tools.jackson.databind.json.JsonMapper;

/**
 * {@linkplain AccessTokenProvider} which handles refresh tokens.
 *
 */

public class StatefulUrlAccessTokenProvider extends AbstractStatefulUrlAccessTokenProvider {

    protected static final Logger logger = LoggerFactory.getLogger(StatefulUrlAccessTokenProvider.class);

    protected final int connectTimeout;
    protected final int readTimeout;
    protected final ObjectReader reader;

    public StatefulUrlAccessTokenProvider(URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers, long connectTimeout, long readTimeout, URL refreshUrl, URL revokeUrl) {
        super(issueUrl, parameters, headers, refreshUrl, revokeUrl);

        checkArgument(connectTimeout > 0 && connectTimeout <= Integer.MAX_VALUE, "Invalid connect timeout value '" + connectTimeout + "'. Must be a positive integer below or equal to " + Integer.MAX_VALUE + ".");
        checkArgument(readTimeout > 0 && readTimeout <= Integer.MAX_VALUE, "Invalid read timeout value '" + readTimeout + "'. Must be a positive integer below or equal to " + Integer.MAX_VALUE + ".");

        this.connectTimeout = (int)connectTimeout;
        this.readTimeout = (int)readTimeout;

        JsonMapper mapper = JsonMapper.builder().build();
        reader = mapper.readerFor(ClientCredentialsResponse.class);
    }

    protected StringBuilder printHeadersIfPresent(HttpURLConnection c, String... headerNames) {
        return UrlAccessTokenProvider.printHttpURLConnectionHeadersIfPresent(c, headerNames);
    }

    @Override
    public boolean supportsHealth() {
        return false;
    }

    protected ClientCredentialsResponse getToken() throws AccessTokenException {
        try {
            HttpURLConnection response = request(issueUrl, issueBody, issueHeaders);

            int responseCode = response.getResponseCode();
            if (responseCode != 200) {
                logger.info("Got unexpected response code {} when trying to issue token at {}", responseCode, issueUrl);
                if (responseCode == 503) { // service unavailable
                    throw new AccessTokenUnavailableException("Authorization server responded with HTTP code 503 - service unavailable. " + printHeadersIfPresent(response, "Retry-After"));
                } else if (responseCode == 429) { // too many calls
                    // see for example https://auth0.com/docs/policies/rate-limits
                    throw new AccessTokenUnavailableException("Authorization server responded with HTTP code 429 - too many requests. " + printHeadersIfPresent(response, "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"));
                }
                throw new AccessTokenException("Authorization server responded with HTTP unexpected response code " + responseCode);
            }
            try (InputStream inputStream = response.getInputStream()) {
                ClientCredentialsResponse clientCredentialsResponse = reader.readValue(inputStream);
                validate(clientCredentialsResponse);
                return clientCredentialsResponse;
            }
        } catch (IOException | JacksonException e) {
            throw new AccessTokenUnavailableException(e);
        }
    }

    protected HttpURLConnection request(URL url, byte[] body, Map<String, Object> headers) throws IOException {
        final HttpURLConnection c = (HttpURLConnection) url.openConnection();
        c.setConnectTimeout(connectTimeout);
        c.setReadTimeout(readTimeout);
        c.setRequestProperty("Accept", "application/json");
        c.setRequestProperty("Content-Type", CONTENT_TYPE);

        for (Entry<String, Object> entry : headers.entrySet()) {
            c.setRequestProperty(entry.getKey(), entry.getValue().toString());
        }

        c.setDoOutput(true);

        try (OutputStream os = c.getOutputStream()) {
            os.write(body);
        }

        return c;
    }

    protected void close(long time) {
        RefreshToken threadSafeRefreshToken = this.refreshToken; // defensive copy
        if (threadSafeRefreshToken != null && threadSafeRefreshToken.isValid(time)) {
            this.refreshToken = null;

            byte[] revokeBody = createRevokeBody(threadSafeRefreshToken);

            try {
                HttpURLConnection request = request(revokeUrl, revokeBody, Collections.emptyMap());
                int responseCode = request.getResponseCode();
                if (responseCode != 200) {
                    logger.info("Unexpected response code {} when revoking refresh token", responseCode);
                }
            } catch (IOException e) {
                logger.warn("Unable to revoke token", e);
            }
        }
    }

    protected ClientCredentialsResponse getToken(RefreshToken response) throws AccessTokenException {
        byte[] refreshBody = createRefreshBody(response);

        try {
            HttpURLConnection request = request(refreshUrl, refreshBody, Collections.emptyMap());

            int responseCode = request.getResponseCode();
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
            try (InputStream inputStream = request.getInputStream()) {
                ClientCredentialsResponse clientCredentialsResponse = reader.readValue(inputStream);
                validate(clientCredentialsResponse);
                return clientCredentialsResponse;
            }
        } catch (IOException e) {
            throw new AccessTokenUnavailableException(e);
        }
    }


}
