package org.entur.jwt.client;

import java.io.Closeable;

/**
 * Provider for {@linkplain AccessToken}. These providers should be closed, 
 * so that (when refresh tokens) sessions are closed.
 * 
 */

public interface AccessTokenProvider extends Closeable, AccessTokenHealthProvider {

	AccessToken getAccessToken(boolean forceRefresh) throws AccessTokenException;

}
