package org.entur.jwt.jwk;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;

/**
 * Jwk provider that loads them from a {@link URL}
 */

public class UrlJwksProvider<T> implements JwksProvider<T> {

	private final URL url;
	private final Integer connectTimeout;
	private final Integer readTimeout;

	private final JwksReader<T> reader;
	/**
	 * Creates a provider that loads from the given URL
	 *
	 * @param url to load the jwks
	 * @param reader Jwk reader / parser
	 */
	public UrlJwksProvider(URL url, JwksReader<T> reader) {
		this(url, reader, null, null);
	}

	/**
	 * Creates a provider that loads from the given URL
	 *
	 * @param url            to load the jwks
	 * @param reader		 Jwk reader / parser
	 * @param connectTimeout connection timeout in milliseconds (null for default)
	 * @param readTimeout    read timeout in milliseconds (null for default)
	 */
	public UrlJwksProvider(URL url, JwksReader<T> reader, Integer connectTimeout, Integer readTimeout) {
		checkArgument(url != null, "A non-null url is required");
		checkArgument(reader != null, "A non-null reader is required");
		checkArgument(connectTimeout == null || connectTimeout >= 0, "Invalid connect timeout value '" + connectTimeout + "'. Must be a non-negative integer.");
		checkArgument(readTimeout == null || readTimeout >= 0, "Invalid read timeout value '" + readTimeout + "'. Must be a non-negative integer.");

		this.url = url;
		this.reader = reader;
		this.connectTimeout = connectTimeout;
		this.readTimeout = readTimeout;
	}

	private void checkArgument(boolean valid, String message) {
		if(!valid) {
			throw new IllegalArgumentException(message);
		}
	}

	public List<T> getJwks(boolean forceUpdate) throws JwksException {
		try {
			final URLConnection c = this.url.openConnection();
			if (connectTimeout != null) {
				c.setConnectTimeout(connectTimeout);
			}
			if (readTimeout != null) {
				c.setReadTimeout(readTimeout);
			}
			c.setRequestProperty("Accept", "application/json");

			try (InputStream inputStream = c.getInputStream()) {
				List<T> jwks = reader.readJwks(inputStream);

				if (jwks == null || jwks.isEmpty()) {
					throw new JwkNotFoundException("No keys found");
				}
				return jwks;
			}
		} catch (InvalidSigningKeysException e) {
			// assume the server returns some kind of generic document, threat this equivalent to
			// an input/output exception.
			throw new JwksUnavailableException("Invalid jwks from url " + url.toString(), e);
		} catch (IOException e) {
			throw new JwksUnavailableException("Cannot obtain jwks from url " + url.toString(), e);
		}
	}

}
