package org.entur.jwt.spring;

import org.entur.jwt.spring.actuate.ListJwksHealthIndicator;
import org.entur.jwt.spring.auth0.properties.JwtProperties;
import org.entur.jwt.spring.auth0.properties.MdcPair;
import org.entur.jwt.spring.auth0.properties.MdcProperties;
import org.entur.jwt.spring.auth0.properties.SecurityProperties;
import org.entur.jwt.spring.auth0.properties.TenantFilter;
import org.entur.jwt.spring.auth0.properties.jwk.JwtTenantProperties;
import org.entur.jwt.spring.filter.log.DefaultJwtMappedDiagnosticContextMapper;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.Executors;

@Configuration
@EnableConfigurationProperties({SecurityProperties.class})
@ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true")
public class JwtAutoConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(JwtAutoConfiguration.class);

    @Bean
    @ConditionalOnMissingBean(JwtMappedDiagnosticContextMapper.class)
    @ConditionalOnProperty(name = {"entur.jwt.mdc.enabled"}, havingValue = "true")
    public JwtMappedDiagnosticContextMapper mapper(SecurityProperties properties) {
        MdcProperties mdc = properties.getJwt().getMdc();
        List<MdcPair> items = mdc.getMappings();
        List<String> to = new ArrayList<>();
        List<String> from = new ArrayList<>();

        // note: possible to map the same claim to different values
        for (MdcPair item : items) {
            to.add(item.getTo());
            from.add(item.getFrom());

            LOG.info("Map JWT claim '{}' to MDC key '{}'", item.getFrom(), item.getTo());
        }
        return new DefaultJwtMappedDiagnosticContextMapper(from, to);
    }

    @Bean(destroyMethod = "close")
    public ListJwksHealthIndicator healthIndicator() {
        return new ListJwksHealthIndicator(1000L, Executors.newCachedThreadPool());
    }

    @Bean(destroyMethod = "close")
    @ConditionalOnMissingBean(JwkSourceMap.class)
    public JwkSourceMap jwkSourceMap(SecurityProperties properties, ListJwksHealthIndicator listJwksHealthIndicator) {
        JwtProperties jwtProperties = properties.getJwt();

        Map<String, JwtTenantProperties> enabledTenants = new HashMap<>();
        for (Entry<String, JwtTenantProperties> entry : jwtProperties.getTenants().entrySet()) {
            if (entry.getValue().isEnabled()) {
                enabledTenants.put(entry.getKey(), entry.getValue());
            }
        }

        Map<String, JwtTenantProperties> tenants;
        TenantFilter filter = jwtProperties.getFilter();
        if (!filter.isEmpty()) {
            tenants = new HashMap<>();

            // filter on key
            for (String id : filter.getIds()) {
                id = id.trim();

                boolean endsWith = id.endsWith("*");

                if (endsWith) {
                    String prefix = id.substring(0, id.length() - 1);
                    for (Entry<String, JwtTenantProperties> entry : enabledTenants.entrySet()) {
                        if (entry.getKey().startsWith(prefix)) {
                            tenants.put(id, entry.getValue());
                        }
                    }
                } else {
                    JwtTenantProperties candidate = enabledTenants.get(id);
                    if (candidate != null) {
                        tenants.put(id, candidate);
                    }
                }
            }
        } else {
            tenants = enabledTenants;
        }
        if (tenants.isEmpty()) {
            Set<String> disabled = new HashSet<>(jwtProperties.getTenants().keySet());
            disabled.removeAll(enabledTenants.keySet());
            if (!filter.isEmpty()) {
                throw new IllegalStateException("No configured tenants for filter '" + filter + "', candidates were " + enabledTenants.keySet() + " (" + disabled + " were disabled)");
            } else {
                throw new IllegalStateException("No configured tenants (" + disabled + " were disabled)");
            }
        }


        JwkSourceMapFactory factory = new JwkSourceMapFactory();

        // add a wrapper so that the verifier is closed on shutdown
        return factory.getJwkSourceMap(tenants, jwtProperties.getJwk(), listJwksHealthIndicator);
    }

    @Bean
    @ConditionalOnMissingBean(TenantsProperties.class)
    public TenantsProperties tenantsProperties(SecurityProperties properties) {
        TenantsProperties tenantsProperties = new TenantsProperties();

        for (Entry<String, JwtTenantProperties> entry : properties.getJwt().getTenants().entrySet()) {
            JwtTenantProperties value = entry.getValue();
            if (value.isEnabled()) {
                tenantsProperties.add(new TenantProperties(entry.getKey(), value.getIssuer(), value.getProperties()));
            }
        }

        return tenantsProperties;
    }

    /*
    @Bean
    @ConditionalOnMissingBean(JwtDetailsMapper.class)
    public JwtDetailsMapper jwtDetailsMapper() {
        return new DefaultJwtDetailsMapper();
    }
*/

    @Bean
    public List<OAuth2TokenValidator<Jwt>> claimConstraints(SecurityProperties properties) {
        OAuth2TokenValidatorFactory oAuth2TokenValidatorFactory = new OAuth2TokenValidatorFactory();

        return oAuth2TokenValidatorFactory.create(properties.getJwt().getClaims());
    }


    /*
    @Bean
    public static BeanDefinitionRegistryPostProcessor jwtClientBeanDefinitionRegistryPostProcessor() {
        // note : adding @Configuration to JwtClientBeanDefinitionRegistryPostProcessor works (as an alternative to @Bean),
        // but gives an ugly warning message.
        return new JwtClientBeanDefinitionRegistryPostProcessor();
    }


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
            add(registry, "newAuth0Instance", enabled(properties.getAuth0()));
            add(registry, "newKeycloakInstance", enabled(properties.getKeycloak()));
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
     */

}
