package org.entur.jwt.spring;

import org.entur.jwt.spring.config.AuthorizationWebSecurityConfig;
import org.entur.jwt.spring.config.JwtFilterWebSecurityConfig;
import org.entur.jwt.spring.filter.JwtServerAuthenticationConverter;
import org.entur.jwt.spring.properties.SecurityProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;

/**
 * This starter exists so that it can be excluded for those wanting to configure their own spring security filter chain.
 * Because of the way the authorization works, the starter only creates a single WebSecurityConfigurerAdapter.
 */

@Configuration
@ConditionalOnClass(WebSecurityConfigurerAdapter.class)
@ConditionalOnExpression("${entur.authorization.enabled:true} || ${entur.jwt.enabled:true}")
@EnableConfigurationProperties({SecurityProperties.class})
@AutoConfigureAfter(JwtAutoConfigurationWebFlux.class)
public class JwtWebSecurityAutoConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(JwtWebSecurityAutoConfiguration.class);

    @Configuration
    @ConditionalOnBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    @ConditionalOnProperty(name = {"entur.authorization.enabled"}, havingValue = "true", matchIfMissing = true)
    public static class AuthorizationConfigurationGuard {

        public AuthorizationConfigurationGuard() {
            throw new IllegalStateException("Authorization does not work for custom spring filter chain. Add 'entur.authorization.enabled=false' or disable this starter using @SpringBootApplication(exclude = {JwtWebSecurityAutoConfiguration.class}).");
        }
    }

    @Configuration
    @ConditionalOnBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = true)
    public static class JwtConfigurationGuard {

        public JwtConfigurationGuard() {
            throw new IllegalStateException("JWT filter does not work for custom spring filter chain. Add 'entur.jwt.enabled=false' or disable this starter using @SpringBootApplication(exclude = {JwtWebSecurityAutoConfiguration.class}).");
        }
    }

    @Configuration
    @ConditionalOnMissingBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    @ConditionalOnExpression("${entur.authorization.enabled:true} && ${entur.jwt.enabled:true}")
    @EnableWebFluxSecurity
    @EnableReactiveMethodSecurity
    public static class CompositeWebSecurityConfiguration {

        private AuthorizationWebSecurityConfig authorizationWebSecurityConfig;
        private JwtFilterWebSecurityConfig jwtFilterWebSecurityConfig;

        // combine everything into the same chain

        @Autowired
        public CompositeWebSecurityConfiguration(SecurityProperties properties, ReactiveAuthenticationManager manager, JwtServerAuthenticationConverter<?> converter, @Autowired(required = false) ServerAuthenticationEntryPoint serverAuthenticationEntryPoint, ServerAuthenticationFailureHandler serverAuthenticationFailureHandler) {
            LOG.info("Configure JWT authentication filter + authorization");
            authorizationWebSecurityConfig = new AuthorizationWebSecurityConfig(properties.getAuthorization()) {
            };
            jwtFilterWebSecurityConfig = new JwtFilterWebSecurityConfig(manager, converter, serverAuthenticationEntryPoint, serverAuthenticationFailureHandler) {
            };
        }

        @Bean
        public SecurityWebFilterChain configure(ServerHttpSecurity http) throws Exception {
            authorizationWebSecurityConfig.configure(http);
            return jwtFilterWebSecurityConfig.configure(http).build();
        }
    }

    @Configuration
    @ConditionalOnMissingBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    @ConditionalOnExpression("${entur.authorization.enabled:true} && !${entur.jwt.enabled:true}")
    @EnableWebFluxSecurity
    @EnableReactiveMethodSecurity
    public static class EnturAuthorizationWebSecurityConfigConfigurerAdapter {

        private AuthorizationWebSecurityConfig authorizationWebSecurityConfig;

        @Autowired
        public EnturAuthorizationWebSecurityConfigConfigurerAdapter(SecurityProperties properties) {
            this.authorizationWebSecurityConfig = new AuthorizationWebSecurityConfig(properties.getAuthorization()) {
            };
        }

        @Bean
        public SecurityWebFilterChain configure(ServerHttpSecurity http) throws Exception {
            LOG.info("Configure authorization");
            return authorizationWebSecurityConfig.configure(http).build();
        }
    }

    @Configuration
    @ConditionalOnMissingBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    @ConditionalOnExpression("!${entur.authorization.enabled:true} && ${entur.jwt.enabled:true}")
    @EnableWebFluxSecurity
    @EnableReactiveMethodSecurity
    public static class EnturJwtFilterWebSecurityConfig {

        private JwtFilterWebSecurityConfig jwtFilterWebSecurityConfig;

        @Autowired
        public EnturJwtFilterWebSecurityConfig(ReactiveAuthenticationManager manager, JwtServerAuthenticationConverter<?> converter, @Autowired(required = false) ServerAuthenticationEntryPoint serverAuthenticationEntryPoint, ServerAuthenticationFailureHandler serverAuthenticationFailureHandler) {
            this.jwtFilterWebSecurityConfig = new JwtFilterWebSecurityConfig(manager, converter, serverAuthenticationEntryPoint, serverAuthenticationFailureHandler) {
            };
        }

        @Bean
        public SecurityWebFilterChain configure(ServerHttpSecurity http){
            LOG.info("Configure JWT authentication filter");

            return jwtFilterWebSecurityConfig.configure(http).build();
        }
    }

}
