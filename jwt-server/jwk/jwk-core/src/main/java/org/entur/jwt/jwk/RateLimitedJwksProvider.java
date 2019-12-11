package org.entur.jwt.jwk;

import java.util.List;

import io.github.bucket4j.Bucket;

/**
 * 
 * {@linkplain JwksProvider} that limits the number of invocations per time
 * unit. This guards against frequent, potentially costly, downstream calls.
 * 
 */

public class RateLimitedJwksProvider<T> extends BaseJwksProvider<T> {

    private final Bucket bucket;

    /**
     * Creates a new provider that will check the given Bucket if a jwks can be
     * provided now.
     *
     * @param bucket   bucket to limit the amount of jwk requested in a given amount
     *                 of time.
     * @param provider provider to use to request jwk when the bucket allows it.
     */
    public RateLimitedJwksProvider(JwksProvider<T> provider, Bucket bucket) {
        super(provider);
        this.bucket = bucket;
    }

    @Override
    public List<T> getJwks(boolean forceUpdate) throws JwksException {
        if (!bucket.tryConsume(1)) {
            throw new RateLimitReachedException();
        }
        return provider.getJwks(forceUpdate);
    }

    Bucket getBucket() {
        return bucket;
    }
}
