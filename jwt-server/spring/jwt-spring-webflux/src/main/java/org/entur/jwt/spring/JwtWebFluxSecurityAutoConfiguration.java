package org.entur.jwt.spring;

import org.entur.jwt.spring.auth0.properties.Auth0Flavour;
import org.entur.jwt.spring.auth0.properties.AuthorizationProperties;
import org.entur.jwt.spring.auth0.properties.Flavours;
import org.entur.jwt.spring.auth0.properties.JwtProperties;
import org.entur.jwt.spring.auth0.properties.KeycloakFlavour;
import org.entur.jwt.spring.auth0.properties.MdcProperties;
import org.entur.jwt.spring.auth0.properties.SecurityProperties;
import org.entur.jwt.spring.config.EnturAuthorizeHttpRequestsCustomizer;
import org.entur.jwt.spring.config.EnturOauth2ResourceServerCustomizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.BeanIds;
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
public class JwtWebFluxSecurityAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(JwtWebFluxSecurityAutoConfiguration.class);

    @Configuration
    @ConditionalOnBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    @ConditionalOnProperty(name = {"entur.authorization.enabled"}, havingValue = "true", matchIfMissing = true)
    public static class AuthorizationConfigurationGuard {

        public AuthorizationConfigurationGuard() {
            throw new IllegalStateException("Authorization does not work for custom spring filter chain. Add 'entur.authorization.enabled=false' or disable this starter using @SpringBootApplication(exclude = {JwtWebSecurityConfigurerAdapterAutoConfiguration.class}).");
        }
    }

    @Configuration
    @ConditionalOnBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
    public static class JwtConfigurationGuard {

        public JwtConfigurationGuard() {
            throw new IllegalStateException("JWT authentication does not work for custom spring filter chain. Add 'entur.jwt.enabled=false' or disable this starter using @SpringBootApplication(exclude = {JwtWebSecurityConfigurerAdapterAutoConfiguration.class}).");
        }
    }

    @Bean
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
    @ConditionalOnMissingBean(JwtAuthorityEnricher.class)
    public JwtAuthorityEnricher jwtAuthorityEnricher() {
        return new DefaultJwtAuthorityEnricher();
    }

    @Configuration
    @ConditionalOnMissingBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    @ConditionalOnExpression("${entur.authorization.enabled:true} || ${entur.jwt.enabled:true}")
    @EnableWebFluxSecurity
    @EnableReactiveMethodSecurity
    public static class CompositeWebSecurityConfigurerAdapter {

        private SecurityProperties securityProperties;

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
                http.authorizeExchange(new EnturAuthorizeHttpRequestsCustomizer(authorization));
            }

            return getSecurityWebFilterChain(http);
        }

        @Bean
        @ConditionalOnExpression("${entur.jwt.enabled:true}")
        public SecurityWebFilterChain jwtSecurityWebFilterChain(
                ServerHttpSecurity http,
                JwkSourceMap jwkSourceMap,
                List<JwtAuthorityEnricher> jwtAuthorityEnrichers,
                List<OAuth2TokenValidator<Jwt>> jwtValidators
        ) throws Exception {

            log.info("Configure with JWT");

            AuthorizationProperties authorization = securityProperties.getAuthorization();
            if (authorization.isEnabled()) {
                http.authorizeExchange(new EnturAuthorizeHttpRequestsCustomizer(authorization));
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

                http.oauth2ResourceServer(new EnturOauth2ResourceServerCustomizer(jwkSourceMap.getJwkSources(), jwtAuthorityEnrichers, jwtValidators));
            }

            MdcProperties mdc = jwt.getMdc();
            if (mdc.isEnabled()) {
                throw new IllegalStateException("MDC not supported for webflux yet");
            }

            // https://www.baeldung.com/spring-prevent-xss
            return getSecurityWebFilterChain(http);
        }

        private static SecurityWebFilterChain getSecurityWebFilterChain(ServerHttpSecurity http) {
            // https://www.baeldung.com/spring-prevent-xss
            http.headers().xssProtection().headerValue(XXssProtectionServerHttpHeadersWriter.HeaderValue.ENABLED_MODE_BLOCK);

            return http
                    .requestCache().requestCache(NoOpServerRequestCache.getInstance()).and()  // Disable WebSession read on every request
                    .csrf().disable()
                    .formLogin().disable()
                    .httpBasic().disable()
                    .logout().disable()
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
