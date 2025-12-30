package org.entur.jwt.client.spring;

import org.entur.jwt.client.AccessTokenProvider;
import org.entur.jwt.client.properties.AbstractJwtClientProperties;
import org.entur.jwt.client.properties.JwtClientCache;
import org.entur.jwt.client.properties.JwtClientProperties;
import org.entur.jwt.client.properties.JwtPreemptiveRefresh;
import org.entur.jwt.client.spring.actuate.AccessTokenProviderHealthIndicator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.ConstructorArgumentValues;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.GenericBeanDefinition;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.health.autoconfigure.contributor.ConditionalOnEnabledHealthIndicator;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.lang.Nullable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

public class JwtClientAutoConfiguration {

    private static Logger log = LoggerFactory.getLogger(JwtClientAutoConfiguration.class);

    protected Long getTimeout(JwtClientProperties properties) {
        return getTimeout(properties.getAuth0(), getTimeout(properties.getKeycloak(), null));
    }

    protected Long getTimeout(Map<String, ? extends AbstractJwtClientProperties> map, Long timeout) {
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
     */

    // https://stackoverflow.com/questions/53462889/create-n-number-of-beans-with-beandefinitionregistrypostprocessor
    public static class JwtClientBeanDefinitionRegistryPostProcessor implements BeanDefinitionRegistryPostProcessor, EnvironmentAware {

        // note: autowiring does not work, must bind via environment
        private JwtClientProperties properties;

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
                    .bind("entur.jwt.clients", JwtClientProperties.class)
                    .orElse(new JwtClientProperties());
        }

        @Override
        public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) {
            // populate default values
            add(registry, "newAuth0Instance", enabled(properties.getAuth0()));
            add(registry, "newKeycloakInstance", enabled(properties.getKeycloak()));
            add(registry, "newGenericInstance", enabled(properties.getGeneric()));
        }

        private Set<String> enabled(Map<String, ? extends AbstractJwtClientProperties> auth0) {
            // order by name
            List<String> enabled = new ArrayList<>();
            for (Entry<String, ? extends AbstractJwtClientProperties> entry : auth0.entrySet()) {
                if (entry.getValue().isEnabled()) {
                    enabled.add(entry.getKey());
                }
            }
            Collections.sort(enabled);
            return new LinkedHashSet<>(enabled);
        }

        private void add(BeanDefinitionRegistry registry, String method, Set<String> keySet) {
            for (String key : keySet) {

                if (registry.containsBeanDefinition(key)) {
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

    @Bean(destroyMethod = "close")
    @ConditionalOnEnabledHealthIndicator("jwts")
    public AccessTokenProviderHealthIndicator jwtsHealthIndicator(Map<String, AccessTokenProvider> providers) {
        // could trigger health update here, but that would interfere with
        // mocking / testing.
        List<String> statusProviders = new ArrayList<>();
        for (Entry<String, AccessTokenProvider> entry : providers.entrySet()) {
            AccessTokenProvider accessTokenProvider = entry.getValue();
            if (accessTokenProvider.supportsHealth()) {
                statusProviders.add(entry.getKey());
            }
        }

        Collections.sort(statusProviders);

        if (statusProviders.isEmpty()) {
            log.warn("Health-indicator is active, but none of the {} access-token provider(s) supports health", providers.size());
        } else {
            log.info("Add health-indicator for {}/{} access-token provider(s) {}", statusProviders.size(), providers.size(), statusProviders.stream().collect(Collectors.joining("', '", "'", "'")));
        }

        AccessTokenProviderHealthIndicator list = new AccessTokenProviderHealthIndicator(Executors.newCachedThreadPool(), "List");

        for (String key : statusProviders) {
            AccessTokenProvider accessTokenProvider = providers.get(key);

            list.addHealthIndicators(key, accessTokenProvider);
        }

        return list;
    }

    @Bean
    public EagerContextStartedListener eagerContextRefreshedListener(Map<String, AccessTokenProvider> providersById, JwtClientProperties springJwtClientProperties) {
        Map<String, AccessTokenProvider> eagerAccessTokenProvidersById = new HashMap<>();

        for (Map<String, ? extends AbstractJwtClientProperties> map : Arrays.asList(springJwtClientProperties.getKeycloak(), springJwtClientProperties.getAuth0())) {
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
