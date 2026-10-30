package org.entur.jwt.client.generic;

import org.entur.jwt.client.AbstractClientCredentialsBuilder;
import org.entur.jwt.client.ClientCredentials;

public class GenericClientCredentialsBuilder extends AbstractClientCredentialsBuilder<GenericClientCredentialsBuilder> {
    public static GenericClientCredentialsBuilder newInstance() {
        return new GenericClientCredentialsBuilder();
    }

    @Override
    public ClientCredentials build() {
        return build(Boolean.TRUE.equals(authorizationHeader));
    }

    // default to client credentials as request parameters, like the Spring configuration
    protected Boolean authorizationHeader = Boolean.FALSE;

    public GenericClientCredentialsBuilder withAuthorizationHeader(Boolean authorizationHeader) {
        this.authorizationHeader = authorizationHeader;
        return this;
    }

    public Boolean getAuthorizationHeader() {
        return authorizationHeader;
    }
}

