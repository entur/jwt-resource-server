package org.entur.jwt.client;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UrlAccessTokenProvider extends AbstractUrlAccessTokenProvider<HttpURLConnection> {

    protected static final Logger logger = LoggerFactory.getLogger(UrlAccessTokenProvider.class);

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

    // https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/

    public UrlAccessTokenProvider(URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers, long connectTimeout, long readTimeout) {
        super(issueUrl, parameters, headers);

        checkArgument(connectTimeout > 0 && connectTimeout <= Integer.MAX_VALUE, "Invalid connect timeout value '" + connectTimeout + "'. Must be a positive integer below or equal to " + Integer.MAX_VALUE + ".");
        checkArgument(readTimeout > 0 && readTimeout <= Integer.MAX_VALUE, "Invalid read timeout value '" + readTimeout + "'. Must be a positive integer below or equal to " + Integer.MAX_VALUE + ".");

        this.connectTimeout = (int)connectTimeout;
        this.readTimeout = (int)readTimeout;
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
    protected int getResponseStatusCode(HttpURLConnection response) throws IOException {
        return response.getResponseCode();
    }

    @Override
    protected InputStream getResponseContent(HttpURLConnection response) throws IOException {
        return response.getInputStream();
    }

    protected StringBuilder printHeadersIfPresent(HttpURLConnection c, String... headerNames) {
        return printHttpURLConnectionHeadersIfPresent(c, headerNames);
    }
    
    @Override
    public boolean supportsHealth() {
        return false;
    }

}
