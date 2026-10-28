package org.entur.jwt.client.spring;

import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.properties.Auth0JwtClientProperties;
import org.entur.jwt.client.properties.GenericJwtClientProperties;
import org.entur.jwt.client.properties.JwtClientProperties;
import org.entur.jwt.client.properties.KeycloakJwtClientProperties;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.ContextStartedEvent;

import java.util.HashMap;
import java.util.Map;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

public class JwtClientAutoConfigurationTest {

    private final JwtClientAutoConfiguration configuration = new JwtClientAutoConfiguration();

    @Test
    public void shouldHaveNoTimeoutWithoutClients() {
        assertThat(configuration.getTimeout(new JwtClientProperties())).isNull();
    }

    @Test
    public void shouldUseLowestCacheRefreshTimeoutOfEnabledClients() {
        JwtClientProperties properties = new JwtClientProperties();

        Auth0JwtClientProperties auth0 = new Auth0JwtClientProperties();
        auth0.getCache().setRefreshTimeout(10);
        properties.getAuth0().put("auth0", auth0);

        KeycloakJwtClientProperties keycloak = new KeycloakJwtClientProperties();
        keycloak.getCache().setRefreshTimeout(8);
        properties.getKeycloak().put("keycloak", keycloak);

        GenericJwtClientProperties generic = new GenericJwtClientProperties();
        generic.getCache().setRefreshTimeout(5);
        properties.getGeneric().put("generic", generic);

        GenericJwtClientProperties disabled = new GenericJwtClientProperties();
        disabled.setEnabled(false);
        disabled.getCache().setRefreshTimeout(1);
        properties.getGeneric().put("disabled", disabled);

        assertThat(configuration.getTimeout(properties)).isEqualTo(5L);
    }

    @Test
    public void shouldUseCacheRefreshTimeoutOfGenericClients() {
        JwtClientProperties properties = new JwtClientProperties();

        GenericJwtClientProperties generic = new GenericJwtClientProperties();
        generic.getCache().setRefreshTimeout(5);
        properties.getGeneric().put("generic", generic);

        assertThat(configuration.getTimeout(properties)).isEqualTo(5L);
    }

    @Test
    public void shouldEagerlyLoadEnabledClientsWithPreemptiveRefresh() throws Exception {
        JwtClientProperties properties = new JwtClientProperties();
        properties.getAuth0().put("auth0", new Auth0JwtClientProperties());
        properties.getKeycloak().put("keycloak", new KeycloakJwtClientProperties());
        properties.getGeneric().put("generic", new GenericJwtClientProperties());

        GenericJwtClientProperties withoutCache = new GenericJwtClientProperties();
        withoutCache.getCache().setEnabled(false);
        properties.getGeneric().put("withoutCache", withoutCache);

        // no provider is registered for disabled clients
        GenericJwtClientProperties disabled = new GenericJwtClientProperties();
        disabled.setEnabled(false);
        properties.getGeneric().put("disabled", disabled);

        Map<String, AccessTokenProvider> providers = new HashMap<>();
        for (String key : new String[] {"auth0", "keycloak", "generic", "withoutCache"}) {
            providers.put(key, mock(AccessTokenProvider.class));
        }

        EagerContextStartedListener listener = configuration.eagerContextRefreshedListener(providers, properties);
        listener.onApplicationEvent(new ContextStartedEvent(mock(ApplicationContext.class)));

        verify(providers.get("auth0")).getAccessToken(false);
        verify(providers.get("keycloak")).getAccessToken(false);
        verify(providers.get("generic")).getAccessToken(false);
        verify(providers.get("withoutCache"), never()).getAccessToken(false);
    }
}
