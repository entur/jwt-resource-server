package org.entur.jwt.client;

import java.util.concurrent.locks.ReentrantLock;

/**
 * Allows one token request at a time. A call made while another is in progress
 * fails immediately with an {@linkplain AccessTokenUnavailableException} instead
 * of waiting or reaching the delegate, so concurrent callers cannot fan out to
 * the authorization server.
 * <br>
 * <br>
 * The builder installs this directly above every built-in HTTP provider, which
 * also keeps the stateful providers' refresh-token session consistent. Caches
 * already serialize their own loads, so this matters most without a cache.
 */

public class ExclusiveAccessTokenProvider extends BaseAccessTokenProvider {

    private final ReentrantLock lock = new ReentrantLock();

    /**
     * Construct a new instance.
     *
     * @param provider delegate that must not be called concurrently
     */
    public ExclusiveAccessTokenProvider(AccessTokenProvider provider) {
        super(provider);
    }

    @Override
    public AccessToken getAccessToken(boolean forceRefresh) throws AccessTokenException {
        if (!lock.tryLock()) {
            throw new AccessTokenUnavailableException("A token request is already in progress");
        }
        try {
            return provider.getAccessToken(forceRefresh);
        } finally {
            lock.unlock();
        }
    }

}
