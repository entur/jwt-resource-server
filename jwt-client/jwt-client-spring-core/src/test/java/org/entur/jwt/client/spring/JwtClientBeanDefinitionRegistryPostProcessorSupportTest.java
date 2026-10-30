package org.entur.jwt.client.spring;

import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.ClientCredentials;
import org.entur.jwt.client.properties.JwtClientProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.mock;

public class JwtClientBeanDefinitionRegistryPostProcessorSupportTest {

    private static class CapturingSupport extends JwtClientBeanDefinitionRegistryPostProcessorSupport<Object> {

        private URL issueUrl;
        private URL refreshUrl;
        private URL revokeUrl;

        public CapturingSupport(JwtClientProperties properties) {
            super(new Object(), properties);
        }

        @Override
        protected AccessTokenProvider newUrlAccessTokenProvider(Object client, URL issueURL, Map<String, Object> parameters, Map<String, Object> headers, ClientCredentials credentials) {
            this.issueUrl = issueURL;
            return mock(AccessTokenProvider.class);
        }

        @Override
        protected AccessTokenProvider newStatefulUrlAccessTokenProvider(Object client, URL issueURL, Map<String, Object> parameters, Map<String, Object> headers, URL refreshUrl, URL revokeUrl, ClientCredentials credentials) {
            this.issueUrl = issueURL;
            this.refreshUrl = refreshUrl;
            this.revokeUrl = revokeUrl;
            return mock(AccessTokenProvider.class);
        }
    }

    private static JwtClientProperties bindKeycloak(Map<String, String> extra) {
        Map<String, String> map = new HashMap<>();
        map.put("entur.jwt.clients.keycloak.myClient.client-id", "myClientId");
        map.put("entur.jwt.clients.keycloak.myClient.secret", "mySecret");
        map.put("entur.jwt.clients.keycloak.myClient.host", "entur.org");
        map.put("entur.jwt.clients.keycloak.myClient.realm", "myTenant");
        map.put("entur.jwt.clients.keycloak.myClient.cache.enabled", "false");
        map.putAll(extra);

        return new Binder(new MapConfigurationPropertySource(map)).bind("entur.jwt.clients", JwtClientProperties.class).get();
    }

    @Test
    public void shouldUseRootKeycloakContextPathByDefault() {
        // i.e. Keycloak 17 and later
        CapturingSupport support = new CapturingSupport(bindKeycloak(Map.of()));

        support.newKeycloakInstance("myClient");

        assertThat(support.issueUrl.toString()).isEqualTo("https://entur.org/realms/myTenant/protocol/openid-connect/token");
        assertThat(support.refreshUrl.toString()).isEqualTo("https://entur.org/realms/myTenant/protocol/openid-connect/token");
        assertThat(support.revokeUrl.toString()).isEqualTo("https://entur.org/realms/myTenant/protocol/openid-connect/logout");
    }

    @Test
    public void shouldUseConfiguredKeycloakContextPath() {
        // i.e. Keycloak versions before 17
        CapturingSupport support = new CapturingSupport(bindKeycloak(Map.of("entur.jwt.clients.keycloak.myClient.context-path", "/auth")));

        support.newKeycloakInstance("myClient");

        assertThat(support.issueUrl.toString()).isEqualTo("https://entur.org/auth/realms/myTenant/protocol/openid-connect/token");
        assertThat(support.refreshUrl.toString()).isEqualTo("https://entur.org/auth/realms/myTenant/protocol/openid-connect/token");
        assertThat(support.revokeUrl.toString()).isEqualTo("https://entur.org/auth/realms/myTenant/protocol/openid-connect/logout");
    }
}
