package org.entur.jwt.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectReader;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
import java.util.Map.Entry;

/**
 * {@linkplain AccessTokenProvider} which handles refresh tokens.
 *
 */

public class StatefulUrlAccessTokenProvider extends AbstractStatefulUrlAccessTokenProvider {

    protected static final Logger LOGGER = LoggerFactory.getLogger(StatefulUrlAccessTokenProvider.class);

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

    @Override
    protected ClientCredentialsResponse getToken() throws AccessTokenException {
        HttpURLConnection response = null;
        try {
            response = request(issueUrl, issueBody, issueHeaders);

            int responseCode = response.getResponseCode();
            if (responseCode != 200) {
                if(LOGGER.isInfoEnabled()) LOGGER.info("Got unexpected response code {} when trying to issue token at {}", responseCode, issueUrl);
                if (responseCode == 503) { // service unavailable
                    throw retryAfterException("Authorization server responded with HTTP code 503 - service unavailable. " + printHeadersIfPresent(response, "Retry-After"),
                            response.getHeaderField("Retry-After"));
                } else if (responseCode == 429) { // too many calls
                    // see for example https://auth0.com/docs/policies/rate-limits
                    throw retryAfterException("Authorization server responded with HTTP code 429 - too many requests. "
                            + printHeadersIfPresent(response, "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"), response.getHeaderField("Retry-After"));
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
        } finally {
            UrlAccessTokenProvider.disconnect(response);
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
        } catch (IOException e) {
            UrlAccessTokenProvider.disconnect(c);
            throw e;
        }

        return c;
    }

    @Override
    protected void close(long time) {
        RefreshToken threadSafeRefreshToken = this.refreshToken; // defensive copy
        if (threadSafeRefreshToken != null && threadSafeRefreshToken.isValid(time)) {
            this.refreshToken = null;

            byte[] revokeBody = createRevokeBody(threadSafeRefreshToken);

            HttpURLConnection request = null;
            try {
                request = request(revokeUrl, revokeBody, revokeHeaders);
                int responseCode = request.getResponseCode();
                if (responseCode < 200 || responseCode > 299) { // i.e. Keycloak responds with 204
                    if (responseCode == 503) { // service unavailable
                        if(LOGGER.isInfoEnabled()) LOGGER.info("Got unexpected response code {} when revoking refresh token at {}. {}", responseCode, revokeUrl, printHeadersIfPresent(request, "Retry-After"));
                    } else if (responseCode == 429) { // too many calls
                        // see for example https://auth0.com/docs/policies/rate-limits
                        if(LOGGER.isInfoEnabled()) LOGGER.info("Got unexpected response code {} when revoking refresh token at {}. {}", responseCode, revokeUrl, printHeadersIfPresent(request, "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"));
                    } else {
                        if(LOGGER.isInfoEnabled()) LOGGER.info("Got unexpected response code {} when revoking refresh token at {}.", responseCode, revokeUrl);
                    }
                }
            } catch (IOException e) {
                LOGGER.warn("Unable to revoke token", e);
            } finally {
                UrlAccessTokenProvider.disconnect(request);
            }
        }
    }

    @Override
    protected ClientCredentialsResponse getToken(RefreshToken response) throws AccessTokenException {
        byte[] refreshBody = createRefreshBody(response);

        HttpURLConnection request = null;
        try {
            request = request(refreshUrl, refreshBody, refreshHeaders);

            int responseCode = request.getResponseCode();
            if (responseCode != 200) {
                if(LOGGER.isInfoEnabled()) LOGGER.info("Got unexpected response code {} when trying to refresh token at {}", responseCode, refreshUrl);
                if (responseCode == 503) { // service unavailable
                    throw retryAfterException("Authorization server responded with HTTP code 503 - service unavailable. " + printHeadersIfPresent(request, "Retry-After"),
                            request.getHeaderField("Retry-After"));
                } else if (responseCode == 429) { // too many calls
                    // see for example https://auth0.com/docs/policies/rate-limits
                    throw retryAfterException("Authorization server responded with HTTP code 429 - too many requests. "
                            + printHeadersIfPresent(request, "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"), request.getHeaderField("Retry-After"));
                }

                throw new RefreshTokenException("Authorization server responded with HTTP unexpected response code " + responseCode);
            }
            try (InputStream inputStream = request.getInputStream()) {
                ClientCredentialsResponse clientCredentialsResponse = reader.readValue(inputStream);
                validate(clientCredentialsResponse);
                return clientCredentialsResponse;
            }
        } catch (IOException | JacksonException e) {
            throw new AccessTokenUnavailableException(e);
        } finally {
            UrlAccessTokenProvider.disconnect(request);
        }
    }


}
