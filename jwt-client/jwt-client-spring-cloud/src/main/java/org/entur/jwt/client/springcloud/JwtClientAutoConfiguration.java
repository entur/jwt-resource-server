package org.entur.jwt.client.springcloud;

import io.netty.channel.ChannelOption;
import io.netty.handler.timeout.ReadTimeoutHandler;
import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.AccessTokenProviderBuilder;
import org.entur.jwt.client.ClientCredentials;
import org.entur.jwt.client.auth0.Auth0ClientCredentialsBuilder;
import org.entur.jwt.client.keycloak.KeycloakClientCredentialsBuilder;
import org.entur.jwt.client.properties.*;
import org.entur.jwt.client.springcloud.actuate.AccessTokenProviderHealthIndicator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.ConstructorArgumentValues;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.GenericBeanDefinition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.lang.Nullable;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Configuration
@EnableConfigurationProperties(SpringJwtClientProperties.class)
public class JwtClientAutoConfiguration {

    @Bean
    @Qualifier("jwtWebClient")
    public WebClient jwtWebClient(WebClient.Builder webClientBuilder, SpringJwtClientProperties properties) {

        long connectTimeout = properties.getConnectTimeout();
        long readTimeout = properties.getReadTimeout();

        Long timeout = getTimeout(properties);

        if(timeout != null) {
            if(connectTimeout > timeout) {
                throw new IllegalArgumentException("Connect timeout of " + connectTimeout + "s exceeds cache refresh time of " + timeout + "s");
            }
            if(readTimeout > timeout) {
                throw new IllegalArgumentException("Read timeout of " + readTimeout + "s exceeds cache refresh time of " + timeout + "s");
            }
        }

        return webClientBuilder.clientConnector(
            new ReactorClientHttpConnector(HttpClient.create()
                .doOnConnected(connection -> connection.addHandler(new ReadTimeoutHandler(((int) readTimeout))))
                                               .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, (int) (connectTimeout*1000))
            )
        ).build();
    }

    private Long getTimeout(SpringJwtClientProperties properties) {
        return getTimeout(properties.getAuth0(), getTimeout(properties.getKeycloak(), null));
    }

    private Long getTimeout(Map<String, ? extends AbstractJwtClientProperties> map, Long timeout) {
        for (Entry<String, ? extends AbstractJwtClientProperties> entry : map.entrySet()) {
            AbstractJwtClientProperties client = entry.getValue();
            if (client.isEnabled()) {
                JwtClientCache cache = client.getCache();
                if (cache != null && cache.isEnabled()) {
                    if (timeout == null) {
                        timeout = cache.getRefreshTimeout();
                    } else {
                        timeout = Math.min(timeout, cache.getRefreshTimeout());
                    }
                }
            }
        }
        return timeout;
    }

    @Bean
    public static BeanDefinitionRegistryPostProcessor jwtClientBeanDefinitionRegistryPostProcessor() {
        // note : adding @Configuration to JwtClientBeanDefinitionRegistryPostProcessor works (as an alternative to @Bean),
        // but gives an ugly warning message.
        return new JwtClientBeanDefinitionRegistryPostProcessor();
    }

    /**
     * Dynamically inject beans with ids so that they can be easily referenced with {@linkplain Qualifier} annotation.
     *
     */

    // https://stackoverflow.com/questions/53462889/create-n-number-of-beans-with-beandefinitionregistrypostprocessor
    public static class JwtClientBeanDefinitionRegistryPostProcessor implements BeanDefinitionRegistryPostProcessor, EnvironmentAware {

        // note: autowiring does not work, must bind via environment
        private SpringJwtClientProperties properties;

        @Override
        public void postProcessBeanFactory(ConfigurableListableBeanFactory factory) {
            // noop
        }

        @Override
        public void setEnvironment(@Nullable Environment environment) {
            bindProperties(environment);
        }

        private void bindProperties(Environment environment) {
            this.properties = Binder.get(environment)
                    .bind("entur.jwt.clients", SpringJwtClientProperties.class)
                    .orElse(new SpringJwtClientProperties());
        }

        @Override
        public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) {
            // populate default values
            add(registry, "newAuth0Instance", properties.getAuth0().keySet());
            add(registry, "newKeycloakInstance", properties.getKeycloak().keySet());
        }

        private void add(BeanDefinitionRegistry registry, String method, Set<String> keySet) {
            for (String key : keySet) {

                if(registry.containsBeanDefinition(key)) {
                    continue;
                }
                GenericBeanDefinition beanDefinition = new GenericBeanDefinition();
                beanDefinition.setBeanClass(AccessTokenProvider.class);
                beanDefinition.setFactoryBeanName("jwtClientBeanDefinitionRegistryPostProcessorSupport");
                beanDefinition.setFactoryMethodName(method);
                beanDefinition.setDestroyMethodName("close");

                ConstructorArgumentValues constructorArgumentValues = new ConstructorArgumentValues();
                constructorArgumentValues.addGenericArgumentValue(key);
                beanDefinition.setAutowireCandidate(true);
                beanDefinition.setConstructorArgumentValues(constructorArgumentValues);

                registry.registerBeanDefinition(key, beanDefinition);
            }
        }
    }

    @Bean
    public JwtClientBeanDefinitionRegistryPostProcessorSupport jwtClientBeanDefinitionRegistryPostProcessorSupport(@Qualifier("jwtWebClient") WebClient webClient, SpringJwtClientProperties properties) {
        return new JwtClientBeanDefinitionRegistryPostProcessorSupport(webClient, properties);
    }

    public static class JwtClientBeanDefinitionRegistryPostProcessorSupport {

        private WebClient webClient;
        private SpringJwtClientProperties rootProperties;

        public JwtClientBeanDefinitionRegistryPostProcessorSupport(WebClient webClient, SpringJwtClientProperties properties) {
            this.webClient = webClient;
            this.rootProperties = properties;
        }

        public AccessTokenProvider newAuth0Instance(String key) {
            Auth0JwtClientProperties properties = rootProperties.getAuth0().get(key);

            ClientCredentials credentials = Auth0ClientCredentialsBuilder.newInstance().withPort(properties.getPort()).withProtocol(properties.getProtocol()).withHost(properties.getHost()).withClientId(properties.getClientId()).withSecret(properties.getSecret()).withScope(properties.getScope())
                    .withAudience(properties.getAudience()).build();
            return toAccessTokenProvider(webClient, properties, credentials, rootProperties.getHealthIndicator().isEnabled());
        }

        public AccessTokenProvider newKeycloakInstance(String key) {
            KeycloakJwtClientProperties properties = this.rootProperties.getKeycloak().get(key);

            ClientCredentials credentials = KeycloakClientCredentialsBuilder.newInstance().withPort(properties.getPort()).withProtocol(properties.getProtocol()).withHost(properties.getHost()).withClientId(properties.getClientId()).withSecret(properties.getSecret()).withScope(properties.getScope())
                    .withAudience(properties.getAudience()).withRealm(properties.getRealm()).build();

            return toAccessTokenProvider(webClient, properties, credentials, this.rootProperties.getHealthIndicator().isEnabled());
        }

        private AccessTokenProvider toAccessTokenProvider(WebClient webClient, AbstractJwtClientProperties properties, ClientCredentials credentials, boolean health) {

            // get connect timeout from cache refresh, if none is specified
            JwtClientCache cache = properties.getCache();

            URL revokeUrl = credentials.getRevokeURL();
            URL refreshUrl = credentials.getRefreshURL();

            AccessTokenProvider accessTokenProvider;
            if (revokeUrl != null && refreshUrl != null) {
                accessTokenProvider = new WebClientStatefulUrlAccessTokenProvider(webClient, credentials.getIssueURL(), credentials.getParameters(), credentials.getHeaders(), refreshUrl, revokeUrl);
            } else if (revokeUrl == null && refreshUrl == null) {
                accessTokenProvider = new WebClientUrlAccessTokenProvider(webClient, credentials.getIssueURL(), credentials.getParameters(), credentials.getHeaders());
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

    }

    @Bean
    @ConditionalOnProperty(value = "entur.jwt.clients.health-indicator.enabled", matchIfMissing = true)
    public AccessTokenProviderHealthIndicator accessTokenProviderHealthIndicator(AccessTokenProvider[] providers) {
        // could verify that health is supported here, but that would interfere with
        // mocking / testing.
        return new AccessTokenProviderHealthIndicator(providers);
    }

    @Bean
    public EagerContextStartedListener eagerContextRefreshedListener(Map<String, AccessTokenProvider> providersById, SpringJwtClientProperties springJwtClientProperties) {
    	Map<String, AccessTokenProvider> eagerAccessTokenProvidersById = new HashMap<>();

    	for(Map<String, ? extends AbstractJwtClientProperties> map : Arrays.asList(springJwtClientProperties.getKeycloak(), springJwtClientProperties.getAuth0())) {
    		for (Entry<String, ? extends AbstractJwtClientProperties> entry : map.entrySet()) {
    			JwtClientCache cache = entry.getValue().getCache();
    			if (cache != null && cache.isEnabled()) {
    				JwtPreemptiveRefresh preemptiveRefresh = cache.getPreemptiveRefresh();
    				if (preemptiveRefresh != null && preemptiveRefresh.isEnabled()) {
    					eagerAccessTokenProvidersById.put(entry.getKey(), providersById.get(entry.getKey()));
    				}
    			}
    		}
    	}
    	return new EagerContextStartedListener(eagerAccessTokenProvidersById);
    }
}
