package org.entur.jwt.client.recovery;

import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * Attempt to recover from an invalid access-token by simply doing a force refresh of the token.
 *
 */

public class DefaultRatelimitedUnauthenticatedAccessTokenRecoveryHandler extends AbstractRatelimitedUnauthenticatedAccessTokenRecoveryHandler {

    private static final Logger log = LoggerFactory.getLogger(DefaultRatelimitedUnauthenticatedAccessTokenRecoveryHandler.class);

    public DefaultRatelimitedUnauthenticatedAccessTokenRecoveryHandler(final long minTimeInterval) {
        super(minTimeInterval);
    }

    @Override
    protected void recover(AccessTokenProvider accessTokenProvider, String header) throws AccessTokenException {
        AccessToken currentAccessToken = accessTokenProvider.getAccessToken(false);
        if (!header.endsWith(currentAccessToken.getValue())) {
            // access-token already refreshed
            log.info("Access-token already refreshed");
            return;
        }
        log.info("Force refreshed access-token");
        accessTokenProvider.getAccessToken(true);
    }
}
