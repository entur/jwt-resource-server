package org.entur.jwt.client.generic;

import org.entur.jwt.client.AbstractClientCredentialsBuilder;
import org.entur.jwt.client.ClientCredentials;

public class GenericClientCredentialsBuilder extends AbstractClientCredentialsBuilder<GenericClientCredentialsBuilder> {
    public static GenericClientCredentialsBuilder newInstance() {
        return new GenericClientCredentialsBuilder();
    }

    @Override
    public ClientCredentials build() {
        return build(authorizationHeader);
    }

    protected Boolean authorizationHeader;

    public GenericClientCredentialsBuilder withAuthorizationHeader(Boolean authorizationHeader) {
        this.authorizationHeader = authorizationHeader;
        return this;
    }

    public Boolean getAuthorizationHeader() {
        return authorizationHeader;
    }
}

