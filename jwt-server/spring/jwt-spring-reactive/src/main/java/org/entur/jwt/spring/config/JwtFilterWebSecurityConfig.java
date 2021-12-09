package org.entur.jwt.spring.config;

import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.filter.JwtAuthenticationFilter;
import org.entur.jwt.spring.properties.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;


/**
 * Default authentication config. Extracted into its own class to allow for customization / override.
 */
@EnableWebFluxSecurity
public abstract class JwtFilterWebSecurityConfig {

    private static Logger log = LoggerFactory.getLogger(JwtAutoConfiguration.class);

    protected static class NoUserDetailsService implements UserDetailsService {
        @Override
        public UserDetails loadUserByUsername(String username) {
            throw new UsernameNotFoundException("");
        }
    }

    protected final JwtAuthenticationFilter<?> filter;
    protected final AuthorizationProperties authorizationProperties;
    protected final JwtProperties jwtProperties;

    @Autowired
    public JwtFilterWebSecurityConfig(JwtAuthenticationFilter<?> filter, AuthorizationProperties authorizationProperties, JwtProperties jwtProperties) {
        this.filter = filter;
        this.authorizationProperties = authorizationProperties;
        this.jwtProperties = jwtProperties;
    }

    @Bean
    public SecurityWebFilterChain configure(ServerHttpSecurity http) throws Exception {
        log.info("Configure JWT filter and authorization filter");

        if (jwtProperties.isEnabled()) {
            http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .logout().disable()
                .cors()
                .and()
                .addFilterBefore(filter, SecurityWebFiltersOrder.FORM_LOGIN);
        }

        if (authorizationProperties.isEnabled()) {
            PermitAll permitAll = authorizationProperties.getPermitAll();
            if (permitAll.isActive()) {
                configurePermitAll(http, permitAll);
            }
            return http.authorizeExchange().anyExchange().authenticated().and().build();
        }
        return http.authorizeExchange().anyExchange().permitAll().and().build();
    }

    protected void configurePermitAll(ServerHttpSecurity http, PermitAll permitAll) throws Exception {

        MatcherConfiguration pathMatcher = permitAll.getPathMatcher();
        if (pathMatcher.isActive()) {
            configurePermitAllPathMatchers(http, pathMatcher);
        }
    }

    protected void configurePermitAllPathMatchers(ServerHttpSecurity http, MatcherConfiguration pathMatchers) throws Exception {
        if (pathMatchers.hasPatterns()) {
            // for all methods
            http.authorizeExchange().pathMatchers(pathMatchers.getPatternsAsArray()).permitAll();
        }

        // for specific methods
        for (HttpMethodMatcher httpMethodMatcher : pathMatchers.getMethod().getActiveMethods()) {
            // check that active, empty patterns will be interpreted as permit all of the method type (empty patterns vs varargs)
            if (httpMethodMatcher.isActive()) {
                http.authorizeExchange().pathMatchers(httpMethodMatcher.getVerb(), httpMethodMatcher.getPatternsAsArray()).permitAll();
            }
        }
    }
}
