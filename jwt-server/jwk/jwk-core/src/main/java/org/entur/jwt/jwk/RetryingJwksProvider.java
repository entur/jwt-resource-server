package org.entur.jwt.jwk;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This provider implements a workaround for transient network problems. <br>
 * <br>
 * It retries getting the list of Jwks if the wrapped provider throws a
 * {@linkplain JwksUnavailableException}.
 */

public class RetryingJwksProvider<T> extends BaseJwksProvider<T> {

    protected static final Logger logger = LoggerFactory.getLogger(RetryingJwksProvider.class);

    public RetryingJwksProvider(JwksProvider<T> provider) {
        super(provider);
    }

    @Override
    public List<T> getJwks(boolean forceUpdate) throws JwksException {
        try {
            return provider.getJwks(forceUpdate);
        } catch (JwksUnavailableException e) {
            // assume transient network issue, retry once
            logger.warn("Recieved exception getting JWKs, retrying once", e);
            
            return provider.getJwks(forceUpdate);
        }
    }

}
