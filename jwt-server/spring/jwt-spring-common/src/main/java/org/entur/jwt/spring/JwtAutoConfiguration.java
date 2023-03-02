package org.entur.jwt.spring;

import org.entur.jwt.spring.actuate.AbstractJwksHealthIndicator;
import org.entur.jwt.spring.auth0.properties.JwtProperties;
import org.entur.jwt.spring.auth0.properties.MdcPair;
import org.entur.jwt.spring.auth0.properties.MdcProperties;
import org.entur.jwt.spring.auth0.properties.SecurityProperties;
import org.entur.jwt.spring.auth0.properties.TenantFilter;
import org.entur.jwt.spring.filter.log.DefaultJwtMappedDiagnosticContextMapper;
import org.entur.jwt.spring.filter.log.JwtMappedDiagnosticContextMapper;
import org.entur.jwt.verifier.JwtClaimExtractor;
import org.entur.jwt.verifier.JwtVerifier;
import org.entur.jwt.verifier.JwtVerifierFactory;
import org.entur.jwt.spring.auth0.properties.jwk.JwtTenantProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

@Configuration
@EnableConfigurationProperties({SecurityProperties.class})
@ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true")
public abstract class JwtAutoConfiguration {

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
    @ConditionalOnMissingBean(JwtVerifier.class)
    public <T> JwtVerifier<T> jwtVerifier(SecurityProperties properties, JwtVerifierFactory<T> factory) {
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

        // add a wrapper so that the verifier is closed on shutdown
        return factory.getVerifier(tenants, jwtProperties.getJwk(), jwtProperties.getClaims());
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

    @Bean
    @ConditionalOnMissingBean(JwtDetailsMapper.class)
    public JwtDetailsMapper jwtDetailsMapper() {
        return new DefaultJwtDetailsMapper();
    }

    @Bean
    @ConditionalOnMissingBean(JwtPrincipalMapper.class)
    public JwtPrincipalMapper jwtPrincipalMapper() {
        return new DefaultJwtPrincipalMapper();
    }

    @Bean
    @ConditionalOnProperty(name = {"entur.jwt.jwk.health-indicator.enabled"}, havingValue = "true", matchIfMissing = true)
    @ConditionalOnBean(JwtVerifier.class)
    public <T> AbstractJwksHealthIndicator jwksHealthIndicator(JwtVerifier<T> verifier) {
        return new AbstractJwksHealthIndicator(verifier, jwkSourceMap);
    }
}
