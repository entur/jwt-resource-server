package org.entur.jwt.client;

import java.net.URL;

public class AccessTokenProviderBuilder extends AbstractAccessTokenProvidersBuilder<AccessTokenProviderBuilder> {

    public static AccessTokenProviderBuilder newBuilder(ClientCredentials credentials, long connectTimeout, long readTimeout) {

        URL revokeUrl = credentials.getRevokeURL();
        URL refreshUrl = credentials.getRefreshURL();

        AccessTokenProvider accessTokenProvider;
        if (revokeUrl == null && refreshUrl != null) {
            throw new IllegalStateException("Expected revoke url when refresh url is present");
        } else if (revokeUrl != null && refreshUrl == null) {
            throw new IllegalStateException("Expected refresh url when revoke url is present");
        } else if (revokeUrl != null && refreshUrl != null) {
            accessTokenProvider = new StatefulUrlAccessTokenProvider(credentials.getIssueURL(), credentials.getParameters(), credentials.getHeaders(), connectTimeout, readTimeout, refreshUrl, revokeUrl);
        } else {
            accessTokenProvider = new UrlAccessTokenProvider(credentials.getIssueURL(), credentials.getParameters(), credentials.getHeaders(), connectTimeout, readTimeout);
        }
        return new AccessTokenProviderBuilder(accessTokenProvider);
    }

    public AccessTokenProviderBuilder(AccessTokenProvider accessTokenProvider) {
        super(accessTokenProvider);
    }

}
