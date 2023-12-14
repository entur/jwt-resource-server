package org.entur.jwt.client.generic;

import static org.junit.jupiter.api.Assertions.*;

import org.entur.jwt.client.ClientCredentials;
import org.junit.jupiter.api.Test;

public class GenericClientCredentialsBuilderTest {
    @Test
    public void testBuilder() {
        ClientCredentials build = GenericClientCredentialsBuilder.newInstance()
                .withHost("my.oauth2server.com")
                .withProtocol("https")
                .withSecret("mySecret")
                .withClientId("myClientID")
                .withIssuePath("v1/oauth/token")
                .build();

        assertNotNull(build.getHeaders());
        assertNotNull(build.getParameters());
        assertNotNull(build.getIssueURL());
        assertNull(build.getRefreshURL());
        assertNull(build.getRevokeURL());
    }
}
