package org.entur.jwt.spring;

import org.entur.jwt.spring.config.JwtFilterWebSecurityConfig;
import org.entur.jwt.spring.filter.JwtAuthenticationFilter;
import org.entur.jwt.spring.properties.SecurityProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * This starter exists so that it can be excluded for those wanting to configure their own spring security filter chain.
 * Because of the way the authorization works, the starter only creates a single WebSecurityConfigurerAdapter.
 */

@Configuration
@ConditionalOnClass(WebSecurityConfigurerAdapter.class)
@ConditionalOnExpression("${entur.authorization.enabled:true} || ${entur.jwt.enabled:true}")
@EnableConfigurationProperties({SecurityProperties.class})
@AutoConfigureAfter(JwtAutoConfiguration.class)
public class JwtWebSecurityAutoConfiguration {

    private static Logger log = LoggerFactory.getLogger(JwtWebSecurityAutoConfiguration.class);

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
            throw new IllegalStateException("JWT filter does not work for custom spring filter chain. Add 'entur.jwt.enabled=false' or disable this starter using @SpringBootApplication(exclude = {JwtWebSecurityConfigurerAdapterAutoConfiguration.class}).");
        }
    }

    @Configuration
    @ConditionalOnMissingBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    @ConditionalOnExpression("${entur.authorization.enabled:true} && ${entur.jwt.enabled:true}")
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    @EnableWebFluxSecurity
    public static class CompositeWebSecurityConfiguration {

        private JwtFilterWebSecurityConfig jwtFilterWebSecurityConfig;

        // combine everything into the same chain

        @Autowired
        public CompositeWebSecurityConfiguration(SecurityProperties properties, JwtAuthenticationFilter<?> filter) {
            log.info("Configure JWT authentication filter + authorization");
            jwtFilterWebSecurityConfig = new JwtFilterWebSecurityConfig(filter, properties.getAuthorization(), properties.getJwt()) {
            };
        }

        @Bean
        public SecurityWebFilterChain configure(ServerHttpSecurity http) throws Exception {
            return jwtFilterWebSecurityConfig.configure(http);
        }
    }

//    @Configuration
//    @ConditionalOnMissingBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
//    @ConditionalOnExpression("${entur.authorization.enabled:true} && !${entur.jwt.enabled:true}")
//    @EnableGlobalMethodSecurity(prePostEnabled = true)
//    public static class EnturAuthorizationWebSecurityConfigConfigurerAdapter extends JwtFilterWebSecurityConfig {
//
//        @Autowired
//        public EnturAuthorizationWebSecurityConfigConfigurerAdapter(SecurityProperties properties) {
//            super(properties.getAuthorization());
//            log.info("Configure authorization");
//        }
//    }

    @Configuration
    @ConditionalOnMissingBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    @ConditionalOnExpression("!${entur.authorization.enabled:true} && ${entur.jwt.enabled:true}")
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    public static class EnturJwtFilterWebSecurityConfig extends JwtFilterWebSecurityConfig {

        @Autowired
        public EnturJwtFilterWebSecurityConfig(JwtAuthenticationFilter<?> filter, SecurityProperties properties) {
            super(filter, properties.getAuthorization(), properties.getJwt());
            log.info("Configure JWT authentication filter and authorization");
        }
    }

}
