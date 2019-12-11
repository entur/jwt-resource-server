package org.entur.jwt.client.keycloak;

import org.entur.jwt.client.AbstractClientCredentialsBuilder;
import org.entur.jwt.client.ClientCredentials;

public class KeycloakClientCredentialsBuilder extends AbstractClientCredentialsBuilder<KeycloakClientCredentialsBuilder> {

    private static final String TEMPLATE = "/auth/realms/%s/protocol/openid-connect";
    private static final String ISSUE_TEMPLATE = TEMPLATE + "/token";
    private static final String REVOKE_TEMPLATE = TEMPLATE + "/logout";

    public static KeycloakClientCredentialsBuilder newInstance() {
        return new KeycloakClientCredentialsBuilder();
    }

    protected String realm;

    @Override
    public ClientCredentials build() {
        if (realm == null) {
            throw new IllegalStateException("Expected realm");
        }
        this.issuePath = String.format(ISSUE_TEMPLATE, realm);
        this.refreshPath = issuePath;
        this.revokePath = String.format(REVOKE_TEMPLATE, realm);

        return build(true); // keycloak supports using the basic authorization header
    }

    public KeycloakClientCredentialsBuilder withRealm(String tenant) {
        this.realm = tenant;
        return this;
    }

    public String getRealm() {
        return realm;
    }
}
