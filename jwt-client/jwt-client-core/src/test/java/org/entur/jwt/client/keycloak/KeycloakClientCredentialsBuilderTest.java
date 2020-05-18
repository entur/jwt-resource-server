package org.entur.jwt.client.keycloak;

import static org.junit.jupiter.api.Assertions.*;

import org.entur.jwt.client.ClientCredentials;
import org.junit.jupiter.api.Test;

public class KeycloakClientCredentialsBuilderTest {

    @Test
    public void testBuilder() {
        ClientCredentials build = KeycloakClientCredentialsBuilder.newInstance().withHost("my.auth0.com").withRealm("myRealm").withProtocol("https").withSecret("mySecret").withClientId("myClientID").build();

        assertNotNull(build.getHeaders());
        assertNotNull(build.getParameters());
        assertNotNull(build.getIssueURL());
        assertNotNull(build.getRefreshURL());
        assertNotNull(build.getRevokeURL());

    }
}
