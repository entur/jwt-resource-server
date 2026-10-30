package org.entur.jwt.spring;

import org.entur.jwt.spring.config.ReactiveEnturAuthorizeHttpRequestsCustomizer;
import org.entur.jwt.spring.config.ReactiveEnturOauth2ResourceServerCustomizer;
import org.entur.jwt.spring.decode.JwtDecoderValidators;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapperDecider;
import org.entur.jwt.spring.decode.cache.DecodedJwtCacheConfigurationReader;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.entur.jwt.spring.properties.Auth0Flavour;
import org.entur.jwt.spring.properties.AuthorizationProperties;
import org.entur.jwt.spring.properties.Flavours;
import org.entur.jwt.spring.properties.JwtProperties;
import org.entur.jwt.spring.properties.KeycloakFlavour;
import org.entur.jwt.spring.properties.MdcProperties;
import org.entur.jwt.spring.properties.SecurityProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.autoconfigure.actuate.web.reactive.ReactiveManagementWebSecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.reactive.ReactiveWebSecurityAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.web.reactive.ReactiveOAuth2ResourceServerWebSecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.header.XXssProtectionServerHttpHeadersWriter;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

/**
 * This starter exists so that it can be excluded for those wanting to configure their own spring security filter chain.
 * Because of the way the authorization works, the starter only creates a single WebSecurityConfigurerAdapter.
 */

@Configuration
@ConditionalOnExpression("${entur.authorization.enabled:true} || ${entur.jwt.enabled:true}")
@EnableConfigurationProperties({SecurityProperties.class})
@AutoConfigureAfter(value = JwtWebFluxAutoConfiguration.class)
// before Spring Boot's default chains, so that only chains defined by the application trip the guards below
@AutoConfigureBefore(value = {ReactiveWebSecurityAutoConfiguration.class, ReactiveManagementWebSecurityAutoConfiguration.class, ReactiveOAuth2ResourceServerWebSecurityAutoConfiguration.class})
public class JwtWebFluxSecurityAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(JwtWebFluxSecurityAutoConfiguration.class);

    // The guards fail startup if the composite configuration backed off because of a custom chain. They are bean
    // methods, as these are evaluated after the nested configurations (which in turn can be evaluated in any order).

    @Bean
    @ConditionalOnBean(SecurityWebFilterChain.class)
    @ConditionalOnMissingBean(CompositeWebSecurityConfigurerAdapter.class)
    @ConditionalOnProperty(name = {"entur.authorization.enabled"}, havingValue = "true", matchIfMissing = true)
    public Object authorizationConfigurationGuard(ListableBeanFactory beanFactory) {
        throw new IllegalStateException("Authorization does not work with custom spring filter chain " + Arrays.toString(beanFactory.getBeanNamesForType(SecurityWebFilterChain.class)) + ". Add 'entur.authorization.enabled=false' or disable this starter using @SpringBootApplication(exclude = {" + JwtWebFluxSecurityAutoConfiguration.class.getSimpleName() + ".class}).");
    }

    @Bean
    @ConditionalOnBean(SecurityWebFilterChain.class)
    @ConditionalOnMissingBean(CompositeWebSecurityConfigurerAdapter.class)
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
    public Object jwtConfigurationGuard(ListableBeanFactory beanFactory) {
        throw new IllegalStateException("JWT authentication does not work with custom spring filter chain " + Arrays.toString(beanFactory.getBeanNamesForType(SecurityWebFilterChain.class)) + ". Add 'entur.jwt.enabled=false' or disable this starter using @SpringBootApplication(exclude = {" + JwtWebFluxSecurityAutoConfiguration.class.getSimpleName() + ".class}).");
    }

    @Bean
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
    @ConditionalOnMissingBean(JwtAuthorityEnricher.class)
    public JwtAuthorityEnricher jwtAuthorityEnricher() {
        return new DefaultJwtAuthorityEnricher();
    }

    @Configuration
    @ConditionalOnMissingBean(SecurityWebFilterChain.class)
    @ConditionalOnExpression("${entur.authorization.enabled:true} || ${entur.jwt.enabled:true}")
    @EnableWebFluxSecurity
    @EnableReactiveMethodSecurity
    public static class CompositeWebSecurityConfigurerAdapter {

        private SecurityProperties securityProperties;

        @Autowired(required = false)
        private JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper;

        @Autowired(required = false)
        private JwtHeaderToIssuerMapperDecider jwtHeaderToIssuerMapperDecider;

        public CompositeWebSecurityConfigurerAdapter(SecurityProperties securityProperties) {
            this.securityProperties = securityProperties;
        }

        @Bean
        @ConditionalOnExpression("${entur.authorization.enabled:true} && !${entur.jwt.enabled:true}")
        public SecurityWebFilterChain securityWebFilterChain(
                ServerHttpSecurity http
        ) throws Exception {
            log.info("Configure without JWT");

            AuthorizationProperties authorization = securityProperties.getAuthorization();
            if (authorization.isEnabled()) {
                http.authorizeExchange(new ReactiveEnturAuthorizeHttpRequestsCustomizer(authorization));
            }

            return getSecurityWebFilterChain(http);
        }

        @Bean
        @ConditionalOnExpression("${entur.jwt.enabled:true}")
        public SecurityWebFilterChain jwtSecurityWebFilterChain(
                ServerHttpSecurity http,
                JwkSourceMap jwkSourceMap,
                List<JwtAuthorityEnricher> jwtAuthorityEnrichers,
                EnturJwtValidators enturJwtValidators,
                ObjectProvider<OAuth2TokenValidator<Jwt>> jwtValidators
        ) throws Exception {

            log.info("Configure with JWT");

            AuthorizationProperties authorization = securityProperties.getAuthorization();
            if (authorization.isEnabled()) {
                http.authorizeExchange(new ReactiveEnturAuthorizeHttpRequestsCustomizer(authorization));
            }

            JwtProperties jwt = securityProperties.getJwt();
            if (jwt.isEnabled()) {

                Flavours flavours = jwt.getFlavours();
                if (flavours.isEnabled()) {
                    List<JwtAuthorityEnricher> enrichers = new ArrayList<>(jwtAuthorityEnrichers);

                    Auth0Flavour auth0 = flavours.getAuth0();
                    if (auth0.isEnabled()) {
                        enrichers.add(new Auth0JwtAuthorityEnricher());
                    }

                    KeycloakFlavour keycloak = flavours.getKeycloak();
                    if (keycloak.isEnabled()) {
                        enrichers.add(new KeycloakJwtAuthorityEnricher());
                    }

                    jwtAuthorityEnrichers = enrichers;
                }

                // the decoded JWT cache is not supported for webflux; warn so the misconfiguration is not silent
                for (String tenant : DecodedJwtCacheConfigurationReader.getTenantsWithDecoderCacheEnabled(jwt)) {
                    log.warn("Tenant '{}' has decoder-cache.enabled=true, but the decoded JWT cache is not supported for webflux; the setting is ignored", tenant);
                }

                // validator beans are used in addition to (not instead of) the library validators
                List<OAuth2TokenValidator<Jwt>> validators = JwtDecoderValidators.combine(enturJwtValidators, jwtValidators.orderedStream(), jwt.getClaims());

                http.oauth2ResourceServer(new ReactiveEnturOauth2ResourceServerCustomizer(jwkSourceMap.getJwkSources(), jwtAuthorityEnrichers, validators, securityProperties.getJwt().getDecode(), jwtHeaderToIssuerMapper, jwtHeaderToIssuerMapperDecider));
            }

            MdcProperties mdc = jwt.getMdc();
            if (mdc.isEnabled() && !mdc.getMappings().isEmpty()) {
                throw new IllegalStateException("MDC mappings are not supported for WebFlux. Remove 'entur.jwt.mdc.mappings' or set 'entur.jwt.mdc.enabled=false'.");
            }

            // https://www.baeldung.com/spring-prevent-xss
            return getSecurityWebFilterChain(http);
        }

        private static SecurityWebFilterChain getSecurityWebFilterChain(ServerHttpSecurity http) {
            // https://www.baeldung.com/spring-prevent-xss
            http.headers( c -> {
               c.xssProtection(x -> {
                 x.headerValue(XXssProtectionServerHttpHeadersWriter.HeaderValue.ENABLED_MODE_BLOCK);
               });
            } );

            return http
                    .requestCache( c -> {
                       c.requestCache(NoOpServerRequestCache.getInstance());
                    })  // Disable WebSession read on every request
                    .csrf(c -> c.disable())
                    .formLogin( c -> c.disable())
                    .httpBasic( c -> c.disable())
                    .logout( c -> c.disable())
                    .cors(Customizer.withDefaults())
                    .build();
        }

        @Bean
        @ConditionalOnMissingBean(MapReactiveUserDetailsService.class)
        public MapReactiveUserDetailsService reactiveUserDetailsService() {
            return new MapReactiveUserDetailsService(new HashMap<>());
        }

        @Bean
        @ConditionalOnMissingBean(UserDetailsService.class)
        public UserDetailsService userDetailsService() {
            return new NoUserDetailsService();
        }
    }

}
