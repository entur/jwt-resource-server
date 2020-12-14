package org.entur.jwt.jwk;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Jwk provider that loads them from a {@link URL}
 */

public class UrlJwksProvider<T> implements JwksProvider<T> {

    protected static final Logger logger = LoggerFactory.getLogger(UrlJwksProvider.class);
    
    protected final URL url;
    protected final int connectTimeout;
    protected final int readTimeout;

    protected final JwksReader<T> reader;

    /**
     * Creates a provider that loads from the given URL
     *
     * @param url            to load the jwks
     * @param reader         Jwk reader / parser
     * @param connectTimeout connection timeout in milliseconds
     * @param readTimeout    read timeout in milliseconds
     */
    public UrlJwksProvider(URL url, JwksReader<T> reader, long connectTimeout, long readTimeout) {
        checkArgument(url != null, "A non-null url is required");
        checkArgument(reader != null, "A non-null reader is required");
        checkArgument(connectTimeout > 0 && connectTimeout <= Integer.MAX_VALUE, "Invalid connect timeout value '" + connectTimeout + "'. Must be a positive integer below or equal to " + Integer.MAX_VALUE + ".");
        checkArgument(readTimeout > 0 && readTimeout <= Integer.MAX_VALUE, "Invalid read timeout value '" + readTimeout + "'. Must be a positive integer below or equal to " + Integer.MAX_VALUE + ".");

        this.url = url;
        this.reader = reader;
        this.connectTimeout = (int)connectTimeout;
        this.readTimeout = (int)readTimeout;
    }

    protected void checkArgument(boolean valid, String message) {
        if (!valid) {
            throw new IllegalArgumentException(message);
        }
    }

    public List<T> getJwks(boolean forceUpdate) throws JwksException {
        logger.info("Requesting JWKs from {}..", url);
        
        try {
            final URLConnection c = this.url.openConnection();
            c.setConnectTimeout(connectTimeout);
            c.setReadTimeout(readTimeout);
            c.setRequestProperty("Accept", "application/json");
            c.setUseCaches(false);
            c.setDoInput(true);
            
            InputStream inputStream = null;
            try {
                inputStream = c.getInputStream();
                
                List<T> jwks = reader.readJwks(inputStream);

                if (jwks == null || jwks.isEmpty()) {
                    // assume the server returns some kind of incomplete document, treat this
                    // equivalent to an input/output exception.
                    throw new JwksTransferException("No JWKs found at " + url);
                }
                logger.info("{} returned {} JWKs", url, jwks.size());
                
                return jwks;
            } finally {
                if(inputStream != null) {
                    inputStream.close();
                }
            }
        } catch (InvalidSigningKeysException e) {
            // assume the server returns some kind of generic document, treat this
            // equivalent to an input/output exception.
            throw new JwksTransferException("Invalid jwks from url " + url.toString(), e);
        } catch (IOException e) {
            throw new JwksTransferException("Cannot obtain jwks from url " + url.toString(), e);
        }
    }

    @Override
    public void close() throws IOException {
        // do nothing
    }

}
