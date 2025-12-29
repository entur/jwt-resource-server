package org.entur.jwt.client;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tools.jackson.core.JacksonException;
import tools.jackson.core.exc.StreamReadException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.ObjectReader;
import tools.jackson.databind.json.JsonMapper;

/**
 * Abstract provider using URL. This simple abstraction exists so that the
 * underlying HTTP client can be swapped.
 *
 */

public abstract class AbstractUrlAccessTokenProvider implements AccessTokenProvider {

    protected static final Logger logger = LoggerFactory.getLogger(AbstractUrlAccessTokenProvider.class);

    protected static final String CONTENT_TYPE = "application/x-www-form-urlencoded";
    protected static final String KEY_GRANT_TYPE = "grant_type";

    protected final URL issueUrl;
    protected final byte[] issueBody;
    protected final Map<String, Object> issueHeaders;

    public AbstractUrlAccessTokenProvider(URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers) {
        super();

        checkArgument(issueUrl != null, "A non-null url is required");
        checkArgument(parameters != null, "A non-null body parameters is required");
        checkArgument(headers != null, "A non-null headers is required");

        this.issueUrl = issueUrl;
        this.issueBody = createBody(parameters);
        this.issueHeaders = headers;
    }

    protected void checkArgument(boolean valid, String message) {
        if (!valid) {
            throw new IllegalArgumentException(message);
        }
    }

    protected byte[] createBody(Map<String, Object> map) {
        StringBuilder builder = new StringBuilder();

        if (!map.isEmpty()) {
            for (Entry<String, Object> entry : map.entrySet()) {
                builder.append(entry.getKey());
                builder.append('=');
                builder.append(encode(entry.getValue().toString()));
                builder.append('&');
            }
            builder.setLength(builder.length() - 1);
        }
        return builder.toString().getBytes(StandardCharsets.UTF_8);
    }

    protected String encode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    protected abstract ClientCredentialsResponse getToken() throws AccessTokenException;

    @Override
    public AccessToken getAccessToken(boolean forceRefresh) throws AccessTokenException {
        long time = System.currentTimeMillis();

        ClientCredentialsResponse token = getToken();

        return new AccessToken(token.getAccessToken(), token.getTokenType(), time + token.getExpiresIn() * 1000);
    }

    @Override
    public void close() throws IOException {
        // NOOP, access-tokens are stateless
    }

    protected void validate(ClientCredentialsResponse clientCredentialsResponse) throws AccessTokenUnavailableException {
        if (clientCredentialsResponse.getExpiresIn() == null) {
            throw new AccessTokenUnavailableException("Expires-in is not specified");
        }
        if (clientCredentialsResponse.getTokenType() == null) {
            throw new AccessTokenUnavailableException("Token-type is not specified");
        }
        if (clientCredentialsResponse.getAccessToken() == null) {
            throw new AccessTokenUnavailableException("Access-token is not specified");
        }
    }
}
