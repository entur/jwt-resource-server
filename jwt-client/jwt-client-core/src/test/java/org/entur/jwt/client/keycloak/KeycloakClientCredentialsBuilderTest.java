package org.entur.jwt.client.keycloak;

import org.entur.jwt.client.ClientCredentials;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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

    @Test
    public void testBuilderWithDefaultContextPath() {
        ClientCredentials build = KeycloakClientCredentialsBuilder.newInstance().withHost("my.keycloak.com").withRealm("myRealm").withSecret("mySecret").withClientId("myClientID").build();

        assertEquals("https://my.keycloak.com/auth/realms/myRealm/protocol/openid-connect/token", build.getIssueURL().toString());
        assertEquals("https://my.keycloak.com/auth/realms/myRealm/protocol/openid-connect/token", build.getRefreshURL().toString());
        assertEquals("https://my.keycloak.com/auth/realms/myRealm/protocol/openid-connect/logout", build.getRevokeURL().toString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "/", " / "})
    public void testBuilderWithRootContextPath(String contextPath) {
        ClientCredentials build = KeycloakClientCredentialsBuilder.newInstance().withHost("my.keycloak.com").withRealm("myRealm").withSecret("mySecret").withClientId("myClientID").withContextPath(contextPath).build();

        assertEquals("https://my.keycloak.com/realms/myRealm/protocol/openid-connect/token", build.getIssueURL().toString());
        assertEquals("https://my.keycloak.com/realms/myRealm/protocol/openid-connect/token", build.getRefreshURL().toString());
        assertEquals("https://my.keycloak.com/realms/myRealm/protocol/openid-connect/logout", build.getRevokeURL().toString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/custom", "/custom/", "custom"})
    public void testBuilderWithCustomContextPath(String contextPath) {
        ClientCredentials build = KeycloakClientCredentialsBuilder.newInstance().withHost("my.keycloak.com").withRealm("myRealm").withSecret("mySecret").withClientId("myClientID").withContextPath(contextPath).build();

        assertEquals("https://my.keycloak.com/custom/realms/myRealm/protocol/openid-connect/token", build.getIssueURL().toString());
        assertEquals("https://my.keycloak.com/custom/realms/myRealm/protocol/openid-connect/logout", build.getRevokeURL().toString());
    }
}
