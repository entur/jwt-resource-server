package org.entur.jwt.spring;

import org.entur.jwt.spring.auth0.properties.AuthorizationProperties;
import org.entur.jwt.spring.auth0.properties.JwtProperties;
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
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@ConditionalOnExpression("${entur.authorization.enabled:true} || ${entur.jwt.enabled:false}")
@EnableConfigurationProperties({SecurityProperties.class})
@AutoConfigureAfter(JwtWebAutoConfiguration.class)
public class JwtWebSecurityChainConfiguration {

    protected static class NoUserDetailsService implements UserDetailsService {
        @Override
        public UserDetails loadUserByUsername(String username) {
            throw new UsernameNotFoundException("");
        }
    }

    private static Logger log = LoggerFactory.getLogger(JwtWebSecurityChainConfiguration.class);

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
            throw new IllegalStateException("JWT authentication does not work for custom spring filter chain. Add 'entur.jwt.enabled=false' or disable this starter using @SpringBootApplication(exclude = {JwtWebSecurityConfigurerAdapterAutoConfiguration.class}).");
        }
    }

    @Bean
    @ConditionalOnProperty(name = {"entur.jwt.enabled"}, havingValue = "true", matchIfMissing = false)
    @ConditionalOnMissingBean(UserDetailsService.class)
    public UserDetailsService userDetailsService() {
        return new NoUserDetailsService();  // avoid the default user.
    }

    @Configuration
    @ConditionalOnMissingBean(name = BeanIds.SPRING_SECURITY_FILTER_CHAIN)
    @ConditionalOnExpression("${entur.authorization.enabled:false} || ${entur.jwt.enabled:false}")
    @EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
    public static class CompositeWebSecurityConfigurerAdapter {

        private SecurityProperties securityProperties;

        public CompositeWebSecurityConfigurerAdapter(SecurityProperties securityProperties) {
            this.securityProperties = securityProperties;
        }

        @Bean
        @ConditionalOnMissingBean(SecurityFilterChain.class)
        public SecurityFilterChain filterChain(HttpSecurity http, JwkSourceMap jwkSourceMap) throws Exception {

            AuthorizationProperties authorization = securityProperties.getAuthorization();
            if (authorization.isEnabled()) {
                http.authorizeHttpRequests(new EnturAuthorizeHttpRequestsCustomizer(authorization));
            }

            JwtProperties jwt = securityProperties.getJwt();
            if (jwt.isEnabled()) {
                http.oauth2ResourceServer(new EnturOauth2ResourceServerCustomizer(jwkSourceMap.getJwkSources()));
            }

            // https://www.baeldung.com/spring-prevent-xss
            http.headers().xssProtection().and()
                    .contentSecurityPolicy("script-src 'self'");

            return http
                    .sessionManagement().sessionCreationPolicy(STATELESS).and()
                    .csrf().disable()
                    .formLogin().disable()
                    .httpBasic().disable()
                    .logout().disable()
                    .cors(Customizer.withDefaults())
                    .build();
        }

    }


}
