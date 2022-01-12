package org.entur.jwt.spring;

import org.entur.jwt.spring.config.AuthorizationWebSecurityConfigurerAdapter;
import org.entur.jwt.spring.config.JwtFilterWebSecurityConfigurerAdapter;
import org.entur.jwt.spring.filter.JwtAuthenticationFilter;
import org.entur.jwt.spring.properties.SecurityProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * This starter exists so that it can be excluded for those wanting to configure their own spring security filter chain.
 * Because of the way the authorization works, the starter only creates a single WebSecurityConfigurerAdapter.
 */

@Configuration
@ConditionalOnClass(WebSecurityConfigurerAdapter.class)
@ConditionalOnExpression("${entur.authorization.enabled:true} || ${entur.jwt.enabled:false}")
@EnableConfigurationProperties({SecurityProperties.class})
@AutoConfigureAfter(JwtAutoConfigurationWeb.class)
public class JwtWebSecurityConfigurerAdapterAutoConfiguration {

    private static Logger log = LoggerFactory.getLogger(JwtWebSecurityConfigurerAdapterAutoConfiguration.class);

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
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = false)
    public static class JwtConfigurationGuard {

        public JwtConfigurationGuard() {
            throw new IllegalStateException("JWT filter does not work for custom spring filter chain. Add 'entur.jwt.enabled=false' or disable this starter using @SpringBootApplication(exclude = {JwtWebSecurityConfigurerAdapterAutoConfiguration.class}).");
        }
    }

    @Configuration
    @ConditionalOnMissingBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    @ConditionalOnExpression("${entur.authorization.enabled:true} && ${entur.jwt.enabled:false}")
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    public static class CompositeWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

        private JwtFilterWebSecurityConfigurerAdapter jwtFilterWebSecurityConfigurerAdapter;
        private AuthorizationWebSecurityConfigurerAdapter authorizationWebSecurityConfigurerAdapter;

        // combine everything into the same chain

        @Autowired
        public CompositeWebSecurityConfigurerAdapter(SecurityProperties properties, JwtAuthenticationFilter<?> filter) {
            log.info("Configure JWT authentication filter + authorization");
            jwtFilterWebSecurityConfigurerAdapter = new JwtFilterWebSecurityConfigurerAdapter(filter) {
            };
            authorizationWebSecurityConfigurerAdapter = new AuthorizationWebSecurityConfigurerAdapter(properties.getAuthorization()) {
            };
        }

        @Bean
        @Override
        public UserDetailsService userDetailsService() {
            return jwtFilterWebSecurityConfigurerAdapter.userDetailsService();
        }

        @Override
        public void configure(HttpSecurity http) throws Exception {
            jwtFilterWebSecurityConfigurerAdapter.configure(http);
            authorizationWebSecurityConfigurerAdapter.configure(http);
        }
    }

    @Configuration
    @ConditionalOnMissingBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    @ConditionalOnExpression("${entur.authorization.enabled:true} && !${entur.jwt.enabled:false}")
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    public static class EnturAuthorizationWebSecurityConfigurerAdapter extends AuthorizationWebSecurityConfigurerAdapter {

        @Autowired
        public EnturAuthorizationWebSecurityConfigurerAdapter(SecurityProperties properties) {
            super(properties.getAuthorization());
            log.info("Configure authorization");
        }
    }

    @Configuration
    @ConditionalOnMissingBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    @ConditionalOnExpression("!${entur.authorization.enabled:true} && ${entur.jwt.enabled:false}")
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    public static class EnturJwtFilterWebSecurityConfigurerAdapter extends JwtFilterWebSecurityConfigurerAdapter {

        @Autowired
        public EnturJwtFilterWebSecurityConfigurerAdapter(JwtAuthenticationFilter<?> filter) {
            super(filter);
            log.info("Configure JWT authentication filter");
        }
    }

}
