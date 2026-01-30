package org.entur.jwt.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

public class StatefulUrlAccessTokenProvider extends AbstractStatefulUrlAccessTokenProvider<HttpURLConnection> {

    protected static final Logger LOGGER = LoggerFactory.getLogger(StatefulUrlAccessTokenProvider.class);

    protected final int connectTimeout;
    protected final int readTimeout;

    public StatefulUrlAccessTokenProvider(URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers, long connectTimeout, long readTimeout, URL refreshUrl, URL revokeUrl) {
        super(issueUrl, parameters, headers, refreshUrl, revokeUrl);

        checkArgument(connectTimeout > 0 && connectTimeout <= Integer.MAX_VALUE, "Invalid connect timeout value '" + connectTimeout + "'. Must be a positive integer below or equal to " + Integer.MAX_VALUE + ".");
        checkArgument(readTimeout > 0 && readTimeout <= Integer.MAX_VALUE, "Invalid read timeout value '" + readTimeout + "'. Must be a positive integer below or equal to " + Integer.MAX_VALUE + ".");

        this.connectTimeout = (int)connectTimeout;
        this.readTimeout = (int)readTimeout;
    }

    @Override
    protected int getResponseStatusCode(HttpURLConnection response) throws IOException {
        return response.getResponseCode();
    }

    @Override
    protected InputStream getResponseContent(HttpURLConnection response) throws IOException {
        return response.getInputStream();
    }

    protected StringBuilder printHeadersIfPresent(HttpURLConnection c, String... headerNames) {
        return UrlAccessTokenProvider.printHttpURLConnectionHeadersIfPresent(c, headerNames);
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

    @Override
    public boolean supportsHealth() {
        return false;
    }

}
