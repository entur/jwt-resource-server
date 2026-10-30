package org.entur.jwt.client.generic;

import org.entur.jwt.client.ClientCredentials;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

    @Test
    public void testBuilderWithDefaultAuthorizationHeader() {
        ClientCredentials build = GenericClientCredentialsBuilder.newInstance()
                .withHost("my.oauth2server.com")
                .withClientId("myClientID")
                .withSecret("mySecret")
                .withIssuePath("v1/oauth/token")
                .build();

        // i.e. client credentials as request parameters
        assertFalse(build.getHeaders().containsKey("Authorization"));
        assertEquals("myClientID", build.getParameters().get("client_id"));
        assertEquals("mySecret", build.getParameters().get("client_secret"));
    }

    @Test
    public void testBuilderWithNullAuthorizationHeader() {
        ClientCredentials build = GenericClientCredentialsBuilder.newInstance()
                .withHost("my.oauth2server.com")
                .withClientId("myClientID")
                .withSecret("mySecret")
                .withIssuePath("v1/oauth/token")
                .withAuthorizationHeader(null)
                .build();

        assertFalse(build.getHeaders().containsKey("Authorization"));
        assertEquals("myClientID", build.getParameters().get("client_id"));
    }
}
