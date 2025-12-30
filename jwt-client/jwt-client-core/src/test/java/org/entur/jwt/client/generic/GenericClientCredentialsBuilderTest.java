package org.entur.jwt.client.generic;

import org.entur.jwt.client.ClientCredentials;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class GenericClientCredentialsBuilderTest {
    @Test
    public void testBuilderWithAuthorizationHeader() {
        ClientCredentials build = GenericClientCredentialsBuilder.newInstance()
                .withHost("my.oauth2server.com")
                .withProtocol("https")
                .withSecret("mySecret")
                .withClientId("myClientID")
                .withIssuePath("v1/oauth/token")
                .withAuthorizationHeader(true)
                .build();

        assertNotNull(build.getHeaders());
        assertNotNull(build.getParameters());
        assertNotNull(build.getIssueURL());
        assertNull(build.getRefreshURL());
        assertNull(build.getRevokeURL());
        assertTrue(build.getHeaders().containsKey("Authorization"));
    }

    @Test
    public void testBuilderWithoutAuthorizationHeader() {
        ClientCredentials build = GenericClientCredentialsBuilder.newInstance()
                .withHost("my.oauth2server.com")
                .withProtocol("https")
                .withSecret("mySecret")
                .withClientId("myClientID")
                .withIssuePath("v1/oauth/token")
                .withAuthorizationHeader(false)
                .build();

        assertNotNull(build.getHeaders());
        assertNotNull(build.getParameters());
        assertNotNull(build.getIssueURL());
        assertNull(build.getRefreshURL());
        assertNull(build.getRevokeURL());
        assertFalse(build.getHeaders().containsKey("Authorization"));
    }
}
