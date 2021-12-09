package org.entur.jwt.spring.config;

import org.entur.jwt.spring.JwtAutoConfiguration;
import org.entur.jwt.spring.properties.AuthorizationProperties;
import org.entur.jwt.spring.properties.HttpMethodMatcher;
import org.entur.jwt.spring.properties.MatcherConfiguration;
import org.entur.jwt.spring.properties.PermitAll;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * Default authorization. Extracted into its own class to allow for customization / override.
 */
@EnableWebFluxSecurity
public abstract class AuthorizationWebSecurityConfig {

    private static Logger log = LoggerFactory.getLogger(JwtAutoConfiguration.class);

    protected final AuthorizationProperties authorizationProperties;

    @Autowired
    public AuthorizationWebSecurityConfig(AuthorizationProperties authorizationProperties) {
        this.authorizationProperties = authorizationProperties;
    }

    @Bean
    public SecurityWebFilterChain configure(ServerHttpSecurity http) throws Exception {
        // implementation note: this filter runs before the dispatcher servlet, and so
        // is out of reach of any ControllerAdvice
        log.info("Configure authorization filter");
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
