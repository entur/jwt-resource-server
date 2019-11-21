package org.entur.jwt.client;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;

public class UrlAccessTokenProvider implements AccessTokenProvider {

	protected static final Logger logger = LoggerFactory.getLogger(UrlAccessTokenProvider.class);

    protected static final String CONTENT_TYPE = "application/x-www-form-urlencoded";
    protected static final String KEY_GRANT_TYPE = "grant_type";
    
	protected final URL issueUrl;
	protected final byte[] issueBody;
	protected final Map<String, Object> issueHeaders;
	
	protected final Integer connectTimeout;
    protected final Integer readTimeout;

	protected final ObjectReader reader;

	// https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/
	
	public UrlAccessTokenProvider(URL issueUrl, Map<String, Object> parameters, Map<String, Object> headers, Integer connectTimeout, Integer readTimeout) {
		super();
		
        checkArgument(issueUrl != null, "A non-null url is required");
        checkArgument(parameters != null, "A non-null body parameters is required");
        checkArgument(headers != null, "A non-null headers is required");
        checkArgument(connectTimeout == null || connectTimeout >= 0, "Invalid connect timeout value '" + connectTimeout + "'. Must be a non-negative integer.");
        checkArgument(readTimeout == null || readTimeout >= 0, "Invalid read timeout value '" + readTimeout + "'. Must be a non-negative integer.");
	
		this.issueUrl = issueUrl;
		this.issueBody = createBody(parameters);
		this.issueHeaders = headers;
		this.connectTimeout = connectTimeout;
		this.readTimeout = readTimeout;
		
		ObjectMapper mapper = new ObjectMapper();
		reader = mapper.readerFor(ClientCredentialsResponse.class);
	}
	
    private void checkArgument(boolean valid, String message) {
		if(!valid) {
			throw new IllegalArgumentException(message);
		}
	}	

	private byte[] createBody(Map<String, Object> map) {
		StringBuilder builder = new StringBuilder();

		if(!map.isEmpty()) {
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
			return URLEncoder.encode(value.toString(), StandardCharsets.UTF_8.name());
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}		
	}

	protected ClientCredentialsResponse getToken() throws  AccessTokenException {
		try {
			HttpURLConnection request = (HttpURLConnection) request(issueUrl, issueBody);
			
			int responseCode = request.getResponseCode();
			if(responseCode != 200) {
				logger.info("Got unexpected response code " + responseCode + " when trying to issue token at " + issueUrl);
				if(responseCode == 503) { // service unavailable
					throw new AccessTokenUnavailableException("Authorization server responded with HTTP code 503 - service unavailable. " + printHeadersIfPresent(request, "Retry-After"));
				} else if(responseCode == 429) { // too many calls
					// see for example https://auth0.com/docs/policies/rate-limits
					throw new AccessTokenUnavailableException("Authorization server responded with HTTP code 429 - too many requests. " + printHeadersIfPresent(request, "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"));
				}
				throw new AccessTokenException("Authorization server responded with HTTP unexpected response code " + request.getResponseCode());
			}
	        try (InputStream inputStream = request.getInputStream()) {
	            return reader.readValue(inputStream);
	        }
		} catch(IOException e) {
			throw new AccessTokenUnavailableException(e);
		}		
	}
	
	protected StringBuilder printHeadersIfPresent(HttpURLConnection c, String ... headerNames) throws IOException {
		StringBuilder builder = new StringBuilder();
		for(String headerName : headerNames) {
			String value = c.getHeaderField(headerName);
			if(value != null) {
				builder.append(headerName);
				builder.append(':');
				builder.append(value);
				builder.append(", ");
			}
		}
		if(builder.length() > 0) {
			builder.setLength(builder.length() - 2);
		}
		return builder;
	}

	protected HttpURLConnection request(URL url, byte[] body) throws IOException {
        final HttpURLConnection c = (HttpURLConnection)url.openConnection();
        if (connectTimeout != null) {
            c.setConnectTimeout(connectTimeout);
        }
        if (readTimeout != null) {
            c.setReadTimeout(readTimeout);
        }
        c.setRequestProperty("Accept", "application/json");
        c.setRequestProperty("Content-Type", CONTENT_TYPE);

        for (Entry<String, Object> entry : issueHeaders.entrySet()) {
            c.setRequestProperty(entry.getKey(), entry.getValue().toString());
		}
        
        c.setDoOutput(true);

        try (OutputStream os = c.getOutputStream()) {
        	os.write(body);
        }
        
        return c;

	}

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
}
