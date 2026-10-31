package org.entur.jwt.client.spring;

import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.AbstractUrlAccessTokenProvider;
import org.entur.jwt.client.ClientCredentials;
import org.entur.jwt.client.PreemptiveCachedAccessTokenProvider;
import org.entur.jwt.client.properties.JwtClientProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class JwtClientBeanDefinitionRegistryPostProcessorSupportTest {

    private static class CapturingSupport extends JwtClientBeanDefinitionRegistryPostProcessorSupport<Object> {

        private URL issueUrl;
        private URL refreshUrl;
        private URL revokeUrl;
        private AbstractUrlAccessTokenProvider httpProvider;

        public CapturingSupport(JwtClientProperties properties) {
            super(new Object(), properties);
        }

        @Override
        protected AccessTokenProvider newUrlAccessTokenProvider(Object client, URL issueURL, Map<String, Object> parameters, Map<String, Object> headers, ClientCredentials credentials) {
            this.issueUrl = issueURL;
            return httpProvider = mock(AbstractUrlAccessTokenProvider.class);
        }

        @Override
        protected AccessTokenProvider newStatefulUrlAccessTokenProvider(Object client, URL issueURL, Map<String, Object> parameters, Map<String, Object> headers, URL refreshUrl, URL revokeUrl, ClientCredentials credentials) {
            this.issueUrl = issueURL;
            this.refreshUrl = refreshUrl;
            this.revokeUrl = revokeUrl;
            return httpProvider = mock(AbstractUrlAccessTokenProvider.class);
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

    @Test
    public void shouldApplyConfiguredErrorCooldowns() throws Exception {
        CapturingSupport support = new CapturingSupport(bindKeycloak(Map.of(
                "entur.jwt.clients.keycloak.myClient.cache.enabled", "true",
                "entur.jwt.clients.keycloak.myClient.cache.refresh-timeout", "7",
                "entur.jwt.clients.keycloak.myClient.cache.preemptive-refresh.error-cooldown", "90",
                "entur.jwt.clients.keycloak.myClient.cache.preemptive-refresh.eager.enabled", "true",
                "entur.jwt.clients.keycloak.myClient.cache.preemptive-refresh.eager.error-cooldown", "120")));

        try (AccessTokenProvider provider = support.newKeycloakInstance("myClient")) {
            PreemptiveCachedAccessTokenProvider cached = (PreemptiveCachedAccessTokenProvider) provider;
            assertThat(cached.getPreemptiveErrorCooldown()).isEqualTo(90_000L);
            assertThat(cached.getEagerErrorCooldown()).isEqualTo(120_000L);
            assertThat(cached.getRefreshTimeout()).isEqualTo(7_000L);
        }
    }

    @Test
    public void shouldApplyDefaultErrorCooldowns() throws Exception {
        CapturingSupport support = new CapturingSupport(bindKeycloak(Map.of(
                "entur.jwt.clients.keycloak.myClient.cache.enabled", "true",
                "entur.jwt.clients.keycloak.myClient.cache.preemptive-refresh.eager.enabled", "true")));

        try (AccessTokenProvider provider = support.newKeycloakInstance("myClient")) {
            PreemptiveCachedAccessTokenProvider cached = (PreemptiveCachedAccessTokenProvider) provider;
            assertThat(cached.getPreemptiveErrorCooldown()).isEqualTo(15_000L);
            assertThat(cached.getEagerErrorCooldown()).isEqualTo(60_000L);
        }
    }

    @Test
    public void shouldConfigureRetryAfterWithoutCaching() throws Exception {
        CapturingSupport support = new CapturingSupport(bindKeycloak(Map.of(
                "entur.jwt.clients.keycloak.myClient.retry-after.fallback-delay", "90")));
        try (AccessTokenProvider provider = support.newKeycloakInstance("myClient")) {
            verify(support.httpProvider).setRetryAfterFallbackMillis(90_000L);
        }
    }
}
