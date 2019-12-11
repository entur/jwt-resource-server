package org.entur.jwt.client.auth0;

import static org.junit.jupiter.api.Assertions.*;

import org.entur.jwt.client.ClientCredentials;
import org.junit.jupiter.api.Test;

public class Auth0ClientCredentialsBuilderTest {

    @Test
    public void testBuilder() {
        ClientCredentials build = Auth0ClientCredentialsBuilder.newInstance().withHost("my.auth0.com").withProtocol("https").withSecret("mySecret").withClientId("myClientID").build();

        assertNotNull(build.getHeaders());
        assertNotNull(build.getParameters());
        assertNotNull(build.getIssueURL());
        assertNull(build.getRefreshURL());
        assertNull(build.getRevokeURL());

    }
}
