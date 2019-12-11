package org.entur.jwt.jwk;

import java.util.List;

/**
 * This provider implements a workaround for transient network problems. <br>
 * <br>
 * It retries getting the list of Jwks if the wrapped provider throws a
 * {@linkplain JwksUnavailableException}.
 */

public class RetryingJwksProvider<T> extends BaseJwksProvider<T> {

    public RetryingJwksProvider(JwksProvider<T> provider) {
        super(provider);
    }

    @Override
    public List<T> getJwks(boolean forceUpdate) throws JwksException {
        try {
            return provider.getJwks(forceUpdate);
        } catch (JwksUnavailableException e) {
            // assume transient network issue, retry once
            return provider.getJwks(forceUpdate);
        }
    }

}
