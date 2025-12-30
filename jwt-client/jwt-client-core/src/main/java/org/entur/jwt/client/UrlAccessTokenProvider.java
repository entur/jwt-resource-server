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

public class UrlAccessTokenProvider extends AbstractUrlAccessTokenProvider {

    protected static final Logger LOGGER = LoggerFactory.getLogger(UrlAccessTokenProvider.class);

    protected static StringBuilder printHttpURLConnectionHeadersIfPresent(HttpURLConnection c, String... headerNames) {
        StringBuilder builder = new StringBuilder();
        for (String headerName : headerNames) {
            String value = c.getHeaderField(headerName);
            if (value != null) {
                builder.append(headerName);
                builder.append(':');
                builder.append(value);
                builder.append(", ");
            }
        }
        if (builder.length() > 0) {
            builder.setLength(builder.length() - 2);
        }
        return builder;
    }

    protected final int connectTimeout;
    protected final int readTimeout;

    protected final ObjectReader reader;

    // https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/

    public UrlAccessTokenProvider(URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers, long connectTimeout, long readTimeout) {
        super(issueUrl, parameters, headers);

        checkArgument(connectTimeout > 0 && connectTimeout <= Integer.MAX_VALUE, "Invalid connect timeout value '" + connectTimeout + "'. Must be a positive integer below or equal to " + Integer.MAX_VALUE + ".");
        checkArgument(readTimeout > 0 && readTimeout <= Integer.MAX_VALUE, "Invalid read timeout value '" + readTimeout + "'. Must be a positive integer below or equal to " + Integer.MAX_VALUE + ".");

        this.connectTimeout = (int)connectTimeout;
        this.readTimeout = (int)readTimeout;

        JsonMapper mapper = JsonMapper.builder().build();
        reader = mapper.readerFor(ClientCredentialsResponse.class);
    }

    protected ClientCredentialsResponse getToken() throws AccessTokenException {
        try {
            HttpURLConnection connection = (HttpURLConnection) issueUrl.openConnection();
            connection.setConnectTimeout(connectTimeout);
            connection.setReadTimeout(readTimeout);
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("Content-Type", CONTENT_TYPE);

            for (Entry<String, Object> entry : issueHeaders.entrySet()) {
                connection.setRequestProperty(entry.getKey(), entry.getValue().toString());
            }

            connection.setDoOutput(true);

            try (OutputStream os = connection.getOutputStream()) {
                os.write(issueBody);
            }

            int responseCode = connection.getResponseCode();
            if (responseCode != 200) {
                if(LOGGER.isInfoEnabled()) LOGGER.info("Got unexpected response code {} when trying to issue token at {}", responseCode, issueUrl);
                if (responseCode == 503) { // service unavailable
                    throw new AccessTokenUnavailableException("Authorization server responded with HTTP code 503 - service unavailable. " + printHeadersIfPresent(connection, "Retry-After"));
                } else if (responseCode == 429) { // too many calls
                    // see for example https://auth0.com/docs/policies/rate-limits
                    throw new AccessTokenUnavailableException("Authorization server responded with HTTP code 429 - too many requests. " + printHeadersIfPresent(connection, "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"));
                }
                throw new AccessTokenException("Authorization server responded with HTTP unexpected response code " + responseCode);
            }
            try (InputStream inputStream = connection.getInputStream()) {
                ClientCredentialsResponse clientCredentialsResponse = reader.readValue(inputStream);
                validate(clientCredentialsResponse);
                return clientCredentialsResponse;
            }
        } catch (IOException | JacksonException e) {
            throw new AccessTokenUnavailableException(e);
        }
    }

    protected StringBuilder printHeadersIfPresent(HttpURLConnection c, String... headerNames) {
        return printHttpURLConnectionHeadersIfPresent(c, headerNames);
    }
    
    @Override
    public boolean supportsHealth() {
        return false;
    }

}
