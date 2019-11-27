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

/**
 * {@linkplain AccessTokenProvider} which handles refresh tokens.
 *
 */

public class StatefulUrlAccessTokenProvider extends AbstractStatefulUrlAccessTokenProvider<HttpURLConnection> {

	protected static final Logger logger = LoggerFactory.getLogger(StatefulUrlAccessTokenProvider.class);

	protected final Integer connectTimeout;
	protected final Integer readTimeout;

	public StatefulUrlAccessTokenProvider(URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers,
			Integer connectTimeout, Integer readTimeout, URL refreshUrl, URL revokeUrl) {
		super(issueUrl, parameters, headers, refreshUrl, revokeUrl);
		
		checkArgument(connectTimeout == null || connectTimeout >= 0, "Invalid connect timeout value '" + connectTimeout + "'. Must be a non-negative integer.");
		checkArgument(readTimeout == null || readTimeout >= 0, "Invalid read timeout value '" + readTimeout + "'. Must be a non-negative integer.");

		this.connectTimeout = connectTimeout;
		this.readTimeout = readTimeout;
	}

	@Override
	protected int getResponseStatusCode(HttpURLConnection response) throws IOException {
		return response.getResponseCode();
	}

	@Override
	protected InputStream getResponseContent(HttpURLConnection response) throws IOException {
		return response.getInputStream();
	}

	protected StringBuilder printHeadersIfPresent(HttpURLConnection c, String ... headerNames) {
		return UrlAccessTokenProvider.printHttpURLConnectionHeadersIfPresent(c, headerNames);
	}
	
	protected HttpURLConnection request(URL url, byte[] body, Map<String, Object> headers) throws IOException {
		final HttpURLConnection c = (HttpURLConnection)url.openConnection();
		if (connectTimeout != null) {
			c.setConnectTimeout(connectTimeout);
		}
		if (readTimeout != null) {
			c.setReadTimeout(readTimeout);
		}
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
}
