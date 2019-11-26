package org.entur.jwt.client.spring;


import java.util.concurrent.TimeUnit;

import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.AccessTokenProviderBuilder;
import org.entur.jwt.client.ClientCredentials;
import org.entur.jwt.client.auth0.Auth0ClientCredentialsBuilder;
import org.entur.jwt.client.keycloak.KeycloakClientCredentialsBuilder;
import org.entur.jwt.client.properties.AbstractJwtClientProperties;
import org.entur.jwt.client.properties.Auth0JwtClientProperties;
import org.entur.jwt.client.properties.JwtClientCache;
import org.entur.jwt.client.properties.KeycloakJwtClientProperties;
import org.entur.jwt.client.properties.PreemptiveRefresh;
import org.entur.jwt.client.spring.actuate.AccessTokenProviderHealthIndicator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(SpringJwtClientProperties.class)
public class JwtClientAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean(AccessTokenProvider.class)
	@ConditionalOnExpression("!'${entur.jwt.client.auth0.client-id:}'.trim().isEmpty()")
	@ConditionalOnProperty(value="entur.jwt.client.auth0.enabled", matchIfMissing = true, havingValue="true")
	public AccessTokenProvider auth0(SpringJwtClientProperties root) {

		Auth0JwtClientProperties properties = root.getAuth0();

		ClientCredentials credentials = Auth0ClientCredentialsBuilder.newInstance()
				.withHost(properties.getHost())
				.withClientId(properties.getClientId())
				.withSecret(properties.getSecret())
				.withScope(properties.getScope())
				.withAudience(properties.getAudience())
				.build();

		return toAccessTokenProvider(properties, credentials, root.getHealthIndicator().isEnabled());
	}

	@Bean
	@ConditionalOnMissingBean(AccessTokenProvider.class)
	@ConditionalOnExpression("!'${entur.jwt.client.keycloak.client-id:}'.trim().isEmpty()")
	@ConditionalOnProperty(value="entur.jwt.client.keycloak.enabled", matchIfMissing = true, havingValue="true")
	public AccessTokenProvider keycloak(SpringJwtClientProperties root) {

		KeycloakJwtClientProperties properties = root.getKeycloak();

		ClientCredentials credentials = KeycloakClientCredentialsBuilder.newInstance()
				.withHost(properties.getHost())
				.withClientId(properties.getClientId())
				.withSecret(properties.getSecret())
				.withScope(properties.getScope())
				.withAudience(properties.getAudience())
				.withRealm(properties.getRealm())
				.build();

		return toAccessTokenProvider(properties, credentials, root.getHealthIndicator().isEnabled());

	}

	private AccessTokenProvider toAccessTokenProvider(AbstractJwtClientProperties properties,
			ClientCredentials credentials, boolean health) {
		Integer connectTimeout = properties.getConnectTimeout();
		Integer readTimeout = properties.getReadTimeout();

		// get connect timeout from cache refresh, if none is specified
		JwtClientCache cache = properties.getCache();
		if(connectTimeout == null && cache != null && cache.isEnabled()) {
			connectTimeout = cache.getRefreshTimeOut();
		}

		AccessTokenProviderBuilder builder = AccessTokenProviderBuilder.newBuilder(credentials, connectTimeout, readTimeout);

		builder.retrying(properties.isRetrying());	

		if(cache != null && cache.isEnabled()) {
			builder.cached(cache.getMinimumTimeToLive(), TimeUnit.SECONDS, cache.getRefreshTimeOut(), TimeUnit.SECONDS);

			PreemptiveRefresh preemptiveRefresh = cache.getPreemptiveRefresh();
			if(preemptiveRefresh != null && preemptiveRefresh.isEnabled()) {
				builder.preemptiveCacheRefresh(preemptiveRefresh.getTime(), TimeUnit.SECONDS);
			} else {
				builder.preemptiveCacheRefresh(false);
			}
		} else {
			builder.cached(false);
		}

		builder.health(health);

		return builder.build();
	}

	@Bean
	@ConditionalOnProperty(value="entur.jwt.client.health-indicator.enabled", matchIfMissing = true)
	@ConditionalOnBean(AccessTokenProvider.class)
	public AccessTokenProviderHealthIndicator provider(AccessTokenProvider provider) {
		// could verify that health is supported here, but that would interfere with mocking / testing.
		return new AccessTokenProviderHealthIndicator(provider);
	}


}
