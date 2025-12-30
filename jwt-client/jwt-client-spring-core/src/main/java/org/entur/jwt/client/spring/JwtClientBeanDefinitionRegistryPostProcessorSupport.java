package org.entur.jwt.client.spring;

import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.AccessTokenProviderBuilder;
import org.entur.jwt.client.ClientCredentials;
import org.entur.jwt.client.auth0.Auth0ClientCredentialsBuilder;
import org.entur.jwt.client.generic.GenericClientCredentialsBuilder;
import org.entur.jwt.client.keycloak.KeycloakClientCredentialsBuilder;
import org.entur.jwt.client.properties.AbstractJwtClientProperties;
import org.entur.jwt.client.properties.Auth0JwtClientProperties;
import org.entur.jwt.client.properties.GenericJwtClientProperties;
import org.entur.jwt.client.properties.JwtClientCache;
import org.entur.jwt.client.properties.JwtClientProperties;
import org.entur.jwt.client.properties.JwtPreemptiveRefresh;
import org.entur.jwt.client.properties.KeycloakJwtClientProperties;

import java.net.URL;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public abstract class JwtClientBeanDefinitionRegistryPostProcessorSupport<T> {

    protected T client;
    protected JwtClientProperties rootProperties;

    public JwtClientBeanDefinitionRegistryPostProcessorSupport(T client, JwtClientProperties properties) {
        this.client = client;
        this.rootProperties = properties;
    }

    public AccessTokenProvider newAuth0Instance(String key) {
        Auth0JwtClientProperties properties = rootProperties.getAuth0().get(key);

        ClientCredentials credentials = Auth0ClientCredentialsBuilder.newInstance()
                .withPort(properties.getPort())
                .withProtocol(properties.getProtocol())
                .withHost(properties.getHost())
                .withClientId(properties.getClientId())
                .withSecret(properties.getSecret())
                .withScope(properties.getScope())
                .withAudience(properties.getAudience())
                .build();
        return toAccessTokenProvider(client, properties, credentials, properties.isHealth());
    }

    public AccessTokenProvider newKeycloakInstance(String key) {
        KeycloakJwtClientProperties properties = this.rootProperties.getKeycloak().get(key);

        ClientCredentials credentials = KeycloakClientCredentialsBuilder.newInstance()
                .withPort(properties.getPort())
                .withProtocol(properties.getProtocol())
                .withHost(properties.getHost())
                .withClientId(properties.getClientId())
                .withSecret(properties.getSecret())
                .withScope(properties.getScope())
                .withAudience(properties.getAudience())
                .withRealm(properties.getRealm())
                .build();

        return toAccessTokenProvider(client, properties, credentials, properties.isHealth());
    }

    public AccessTokenProvider newGenericInstance(String key) {
        GenericJwtClientProperties properties = this.rootProperties.getGeneric().get(key);

        ClientCredentials credentials = GenericClientCredentialsBuilder.newInstance()
                .withPort(properties.getPort())
                .withProtocol(properties.getProtocol())
                .withHost(properties.getHost())
                .withClientId(properties.getClientId())
                .withSecret(properties.getSecret())
                .withScope(properties.getScope())
                .withAudience(properties.getAudience())
                .withIssuePath(properties.getIssuePath())
                .withRefreshPath(properties.getRefreshPath())
                .withRevokePath(properties.getRevokePath())
                .withAuthorizationHeader(
                        properties.getClientCredentialsRequestFormat() == GenericJwtClientProperties.ClientCredentialsRequestFormat.AUTHORIZATION_HEADER
                )
                .build();

        return toAccessTokenProvider(client, properties, credentials, properties.isHealth());
    }

    private AccessTokenProvider toAccessTokenProvider(T client, AbstractJwtClientProperties properties, ClientCredentials credentials, boolean health) {

        // get connect timeout from cache refresh, if none is specified
        JwtClientCache cache = properties.getCache();

        URL revokeUrl = credentials.getRevokeURL();
        URL refreshUrl = credentials.getRefreshURL();

        AccessTokenProvider accessTokenProvider;
        if (revokeUrl != null && refreshUrl != null) {
            accessTokenProvider = newStatefulUrlAccessTokenProvider(client, credentials.getIssueURL(), credentials.getParameters(), credentials.getHeaders(), refreshUrl, revokeUrl, credentials);
        } else if (revokeUrl == null && refreshUrl == null) {
            accessTokenProvider = newUrlAccessTokenProvider(client, credentials.getIssueURL(), credentials.getParameters(), credentials.getHeaders(), credentials);
        } else {
            throw new IllegalStateException("Expected neither or both refresh url and revoke url present");
        }

        AccessTokenProviderBuilder builder = new AccessTokenProviderBuilder(accessTokenProvider);

        builder.retrying(properties.isRetrying());

        if (cache != null && cache.isEnabled()) {
            builder.cached(cache.getMinimumTimeToLive(), TimeUnit.SECONDS, cache.getRefreshTimeout(), TimeUnit.SECONDS);

            JwtPreemptiveRefresh preemptiveRefresh = cache.getPreemptiveRefresh();
            if (preemptiveRefresh != null && preemptiveRefresh.isEnabled()) {
                builder.preemptiveCacheRefresh(preemptiveRefresh.getTimeToExpires(), TimeUnit.SECONDS, preemptiveRefresh.getExpiresConstraint(), preemptiveRefresh.getEager().isEnabled());
            } else {
                builder.preemptiveCacheRefresh(false);
            }
        } else {
            builder.cached(false);
        }

        builder.health(health);

        return builder.build();
    }

    protected abstract AccessTokenProvider newUrlAccessTokenProvider(T client, URL issueURL, Map<String, Object> parameters, Map<String, Object> headers, ClientCredentials credentials);

    protected abstract AccessTokenProvider newStatefulUrlAccessTokenProvider(T client, URL issueURL, Map<String, Object> parameters, Map<String, Object> headers, URL refreshUrl, URL revokeUrl, ClientCredentials credentials);

}