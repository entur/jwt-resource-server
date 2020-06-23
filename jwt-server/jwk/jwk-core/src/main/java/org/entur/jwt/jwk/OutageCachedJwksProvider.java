package org.entur.jwt.jwk;

import java.time.Duration;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This provider implements a workaround for temporary network problems /
 * downtime, running into minutes or hours.<br>
 * <br>
 * 
 * It transparently caches a delegate {@linkplain JwksProvider}, returning the
 * cached value only when the underlying delegate throws a
 * {@linkplain JwksUnavailableException}.
 */

public class OutageCachedJwksProvider<T> extends AbstractCachedJwksProvider<T> {

    protected static final Logger logger = LoggerFactory.getLogger(OutageCachedJwksProvider.class);

    public OutageCachedJwksProvider(JwksProvider<T> delegate, Duration duration) {
        super(delegate, duration.toMillis());
    }

    @Override
    List<T> getJwks(long time, boolean forceUpdate) throws JwksException {
        try {
            // cache value, if successfully refreshed by underlying provider

            List<T> all = provider.getJwks(forceUpdate);

            this.cache = new JwkListCacheItem<T>(all, getExpires(time));

            return all;
        } catch (JwksUnavailableException e1) {
            // attempt to get from underlying cache
            // reuse previously stored value
            if (!forceUpdate) {
                JwkListCacheItem<T> cache = this.cache;
                if (cache != null && cache.isValid(time)) {
                    long left = cache.getExpires() - time; // in millis

                    // so validation of tokens will still work, but fail as soon as this cache
                    // expires
                    // note that issuing new tokens will probably not work when this operation does
                    // not work either.
                    //
                    // logging scheme:
                    // 50% time left, or less than one hour -> error
                    // 50-100% time left -> warning

                    long minutes = (left % 3600000) / 60000;
                    long hours = left / 3600000;

                    long percent = (left * 100) / timeToLive;

                    String message = "Unable to refresh keys for verification of Json Web Token signatures: " + e1.toString() + ". If this is not resolved, all incoming requests with authorization will fail as outage cache expires in "
                            + hours + " hours and " + minutes + " minutes.";
                    if (percent < 50 || hours == 0) {
                        logger.error(message);
                    } else {
                        logger.warn(message);
                    }

                    return cache.getValue();
                }
            }

            throw e1;
        }
    }

}
