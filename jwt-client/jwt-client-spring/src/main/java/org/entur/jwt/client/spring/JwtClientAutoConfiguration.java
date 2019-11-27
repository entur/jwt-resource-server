package org.entur.jwt.client.spring;


import java.net.URL;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
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
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
@EnableConfigurationProperties(SpringJwtClientProperties.class)
public class JwtClientAutoConfiguration {

	@Bean
	@Qualifier("jwtRestTemplate")
	public RestTemplate jwtRestTemplate(RestTemplateBuilder restTemplateBuilder, SpringJwtClientProperties properties) {
		
		Integer connectTimeout = properties.getConnectTimeout();
		Integer readTimeout = properties.getReadTimeout();

		// get connect timeout from cache refresh, if none is specified
		if(connectTimeout == null || readTimeout == null) {
			Integer timeout = null;
			AbstractJwtClientProperties[] clients = new AbstractJwtClientProperties[] {properties.getAuth0(), properties.getKeycloak()};
			for(AbstractJwtClientProperties client : clients) {
				if(client.isEnabled()) {
					JwtClientCache cache = client.getCache();
					if(cache != null && cache.isEnabled()) {
						if(timeout == null) {
							timeout = cache.getRefreshTimeout();
						} else {
							timeout = Math.min(timeout, cache.getRefreshTimeout());
						}
					}
				}
			}
			if(connectTimeout == null) {
				connectTimeout = timeout;
			}
			if(readTimeout == null) {
				readTimeout = timeout;
			}
		}

		if(connectTimeout != null) {
			restTemplateBuilder = restTemplateBuilder.setConnectTimeout(Duration.of(connectTimeout.longValue(), ChronoUnit.SECONDS));
		}
		if(readTimeout != null) {
			restTemplateBuilder = restTemplateBuilder.setReadTimeout(Duration.of(readTimeout.longValue(), ChronoUnit.SECONDS));
		}
		
		return restTemplateBuilder.build();
	}

	@Bean
	@ConditionalOnMissingBean(AccessTokenProvider.class)
	@ConditionalOnExpression("!'${entur.jwt.client.auth0.client-id:}'.trim().isEmpty()")
	@ConditionalOnProperty(value="entur.jwt.client.auth0.enabled", matchIfMissing = true, havingValue="true")
	public AccessTokenProvider auth0(SpringJwtClientProperties root, @Qualifier("jwtRestTemplate") RestTemplate restTemplate) {

		Auth0JwtClientProperties properties = root.getAuth0();

		ClientCredentials credentials = Auth0ClientCredentialsBuilder.newInstance()
				.withHost(properties.getHost())
				.withClientId(properties.getClientId())
				.withSecret(properties.getSecret())
				.withScope(properties.getScope())
				.withAudience(properties.getAudience())
				.build();

		return toAccessTokenProvider(restTemplate, properties, credentials, root.getHealthIndicator().isEnabled());
	}

	@Bean
	@ConditionalOnMissingBean(AccessTokenProvider.class)
	@ConditionalOnExpression("!'${entur.jwt.client.keycloak.client-id:}'.trim().isEmpty()")
	@ConditionalOnProperty(value="entur.jwt.client.keycloak.enabled", matchIfMissing = true, havingValue="true")
	public AccessTokenProvider keycloak(SpringJwtClientProperties root, @Qualifier("jwtRestTemplate") RestTemplate restTemplate) {

		KeycloakJwtClientProperties properties = root.getKeycloak();

		ClientCredentials credentials = KeycloakClientCredentialsBuilder.newInstance()
				.withHost(properties.getHost())
				.withClientId(properties.getClientId())
				.withSecret(properties.getSecret())
				.withScope(properties.getScope())
				.withAudience(properties.getAudience())
				.withRealm(properties.getRealm())
				.build();

		return toAccessTokenProvider(restTemplate, properties, credentials, root.getHealthIndicator().isEnabled());

	}

	private AccessTokenProvider toAccessTokenProvider(RestTemplate restTemplate, AbstractJwtClientProperties properties,
			ClientCredentials credentials, boolean health) {

		// get connect timeout from cache refresh, if none is specified
		JwtClientCache cache = properties.getCache();

		URL revokeUrl = credentials.getRevokeURL();
		URL refreshUrl = credentials.getRefreshURL();

		AccessTokenProvider accessTokenProvider;
		if(revokeUrl != null && refreshUrl != null) {
			accessTokenProvider = new RestTemplateStatefulUrlAccessTokenProvider(restTemplate, credentials.getIssueURL(), credentials.getParameters(), credentials.getHeaders(), refreshUrl, revokeUrl);
		} else if(revokeUrl == null && refreshUrl == null) {
			accessTokenProvider = new RestTemplateUrlAccessTokenProvider(restTemplate, credentials.getIssueURL(), credentials.getParameters(), credentials.getHeaders());
		} else {
			throw new IllegalStateException("Expected neither or both refresh url and revoke url present");
		}
		
		AccessTokenProviderBuilder builder = new AccessTokenProviderBuilder(accessTokenProvider);

		builder.retrying(properties.isRetrying());	

		if(cache != null && cache.isEnabled()) {
			builder.cached(cache.getMinimumTimeToLive(), TimeUnit.SECONDS, cache.getRefreshTimeout(), TimeUnit.SECONDS);

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
