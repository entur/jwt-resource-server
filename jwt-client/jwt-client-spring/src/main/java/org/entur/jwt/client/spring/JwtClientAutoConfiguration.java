package org.entur.jwt.client.spring;

import java.net.URL;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
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
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.ConstructorArgumentValues;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.GenericBeanDefinition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.lang.Nullable;
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
        if (connectTimeout == null || readTimeout == null) {
            Integer timeout = getTimeout(properties);
            
            if (connectTimeout == null) {
                connectTimeout = timeout;
            }
            if (readTimeout == null) {
                readTimeout = timeout;
            }
        }

        if (connectTimeout != null) {
            restTemplateBuilder = restTemplateBuilder.setConnectTimeout(Duration.of(connectTimeout.longValue(), ChronoUnit.SECONDS));
        }
        if (readTimeout != null) {
            restTemplateBuilder = restTemplateBuilder.setReadTimeout(Duration.of(readTimeout.longValue(), ChronoUnit.SECONDS));
        }

        return restTemplateBuilder.build();
    }
    
    private Integer getTimeout(SpringJwtClientProperties properties) {
        return getTimeout(properties.getAuth0(), getTimeout(properties.getKeycloak(), null));
    }

    private Integer getTimeout(Map<String, ? extends AbstractJwtClientProperties> map, Integer timeout) {
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

    
    /**
     * Dynamically inject beans with ids so that they can be easily referenced with {@linkplain Qualifier} annotation. 
     * 
     */
    
    // https://stackoverflow.com/questions/53462889/create-n-number-of-beans-with-beandefinitionregistrypostprocessor
    @Configuration
    public static class JwtClientBeanDefinitionRegistryPostProcessor implements BeanDefinitionRegistryPostProcessor, EnvironmentAware {

        // note: autowiring does not work
        private SpringJwtClientProperties properties;
        
        @Override
        public void postProcessBeanFactory(ConfigurableListableBeanFactory factory) throws BeansException {
            
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
        public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
            // populate default values
            add(registry, "newAuth0Instance", properties.getAuth0().keySet());
            add(registry, "newKeycloakInstance", properties.getKeycloak().keySet());
        }

        private void add(BeanDefinitionRegistry registry, String method, Set<String> keySet) {
            for (String key : keySet) {
                GenericBeanDefinition beanDefinition = new GenericBeanDefinition();
                beanDefinition.setBeanClass(AccessTokenProvider.class);
                beanDefinition.setFactoryBeanName("jwtClientBeanDefinitionRegistryPostProcessorSupport");
                beanDefinition.setFactoryMethodName(method);
                ConstructorArgumentValues constructorArgumentValues = new ConstructorArgumentValues();
                constructorArgumentValues.addGenericArgumentValue(key);
                
                beanDefinition.setConstructorArgumentValues(constructorArgumentValues);
                
                registry.registerBeanDefinition(key, beanDefinition);
            }
        }
    }
    
    @Bean
    public JwtClientBeanDefinitionRegistryPostProcessorSupport jwtClientBeanDefinitionRegistryPostProcessorSupport(@Qualifier("jwtRestTemplate") RestTemplate restTemplate, SpringJwtClientProperties properties) {
        return new JwtClientBeanDefinitionRegistryPostProcessorSupport(restTemplate, properties);
    }
    
    public static class JwtClientBeanDefinitionRegistryPostProcessorSupport {
        
        private RestTemplate restTemplate;
        private SpringJwtClientProperties rootProperties;
        
        public JwtClientBeanDefinitionRegistryPostProcessorSupport(RestTemplate restTemplate, SpringJwtClientProperties properties) {
            this.restTemplate = restTemplate;
            this.rootProperties = properties;
        }
        
        public AccessTokenProvider newAuth0Instance(String key) {
            Auth0JwtClientProperties properties = rootProperties.getAuth0().get(key);
         
            ClientCredentials credentials = Auth0ClientCredentialsBuilder.newInstance().withHost(properties.getHost()).withClientId(properties.getClientId()).withSecret(properties.getSecret()).withScope(properties.getScope())
                    .withAudience(properties.getAudience()).build();
            return toAccessTokenProvider(restTemplate, properties, credentials, rootProperties.getHealthIndicator().isEnabled());
        }

        public AccessTokenProvider newKeycloakInstance(String key) {
            KeycloakJwtClientProperties properties = this.rootProperties.getKeycloak().get(key);
         
            ClientCredentials credentials = KeycloakClientCredentialsBuilder.newInstance().withHost(properties.getHost()).withClientId(properties.getClientId()).withSecret(properties.getSecret()).withScope(properties.getScope())
                    .withAudience(properties.getAudience()).withRealm(properties.getRealm()).build();

            return toAccessTokenProvider(restTemplate, properties, credentials, this.rootProperties.getHealthIndicator().isEnabled());
        }

        private AccessTokenProvider toAccessTokenProvider(RestTemplate restTemplate, AbstractJwtClientProperties properties, ClientCredentials credentials, boolean health) {

            // get connect timeout from cache refresh, if none is specified
            JwtClientCache cache = properties.getCache();

            URL revokeUrl = credentials.getRevokeURL();
            URL refreshUrl = credentials.getRefreshURL();

            AccessTokenProvider accessTokenProvider;
            if (revokeUrl != null && refreshUrl != null) {
                accessTokenProvider = new RestTemplateStatefulUrlAccessTokenProvider(restTemplate, credentials.getIssueURL(), credentials.getParameters(), credentials.getHeaders(), refreshUrl, revokeUrl);
            } else if (revokeUrl == null && refreshUrl == null) {
                accessTokenProvider = new RestTemplateUrlAccessTokenProvider(restTemplate, credentials.getIssueURL(), credentials.getParameters(), credentials.getHeaders());
            } else {
                throw new IllegalStateException("Expected neither or both refresh url and revoke url present");
            }

            AccessTokenProviderBuilder builder = new AccessTokenProviderBuilder(accessTokenProvider);

            builder.retrying(properties.isRetrying());

            if (cache != null && cache.isEnabled()) {
                builder.cached(cache.getMinimumTimeToLive(), TimeUnit.SECONDS, cache.getRefreshTimeout(), TimeUnit.SECONDS);

                PreemptiveRefresh preemptiveRefresh = cache.getPreemptiveRefresh();
                if (preemptiveRefresh != null && preemptiveRefresh.isEnabled()) {
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
        
    }

    @Bean
    @ConditionalOnProperty(value = "entur.jwt.clients.health-indicator.enabled", matchIfMissing = true)
    public AccessTokenProviderHealthIndicator provider(AccessTokenProvider[] providers) {
        // could verify that health is supported here, but that would interfere with
        // mocking / testing.
        return new AccessTokenProviderHealthIndicator(providers);
    }

}
