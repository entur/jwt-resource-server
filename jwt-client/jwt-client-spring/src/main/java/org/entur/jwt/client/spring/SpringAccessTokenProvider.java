package org.entur.jwt.client.spring;

import java.io.IOException;

import javax.annotation.PreDestroy;

import org.entur.jwt.client.AccessToken;
import org.entur.jwt.client.AccessTokenException;
import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.BaseAccessTokenProvider;

/**
 * Wrapper with pre-destroy call to {@linkplain #close()}.
 * 
 */

public class SpringAccessTokenProvider extends BaseAccessTokenProvider {

    public SpringAccessTokenProvider(AccessTokenProvider delegate) {
        super(delegate);
    }

    @PreDestroy
    public void cancelBackgroundRefreshes() {
        try {
            provider.close();
        } catch (IOException e) {
            // ignore
        }
    }

    @Override
    public AccessToken getAccessToken(boolean forceRefresh) throws AccessTokenException {
        return provider.getAccessToken(forceRefresh);
    }
    
}
