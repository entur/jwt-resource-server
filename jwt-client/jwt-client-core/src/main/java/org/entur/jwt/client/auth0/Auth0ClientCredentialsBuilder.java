package org.entur.jwt.client.auth0;

import org.entur.jwt.client.AbstractClientCredentialsBuilder;
import org.entur.jwt.client.ClientCredentials;

public class Auth0ClientCredentialsBuilder extends AbstractClientCredentialsBuilder<Auth0ClientCredentialsBuilder> {

    public static Auth0ClientCredentialsBuilder newInstance() {
        return new Auth0ClientCredentialsBuilder().withIssuePath("/oauth/token");
    }

    @Override
    public ClientCredentials build() {
        return build(false); // auth0 does not support using the basic authorization header
    }

}
