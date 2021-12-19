package org.entur.jwt.spring.config;

import org.entur.jwt.spring.properties.AuthorizationProperties;
import org.entur.jwt.spring.properties.HttpMethodMatcher;
import org.entur.jwt.spring.properties.MatcherConfiguration;
import org.entur.jwt.spring.properties.PermitAll;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.web.server.ServerHttpSecurity;

/**
 * Default authorization. Extracted into its own class to allow for customization / override.
 */
public abstract class AuthorizationWebSecurityConfig {

    private static Logger log = LoggerFactory.getLogger(AuthorizationWebSecurityConfig.class);

    protected final AuthorizationProperties authorizationProperties;

    @Autowired
    public AuthorizationWebSecurityConfig(AuthorizationProperties authorizationProperties) {
        this.authorizationProperties = authorizationProperties;
    }

    public ServerHttpSecurity configure(ServerHttpSecurity http) throws Exception {
        log.info("Configure authorization filter");
        if (authorizationProperties.isEnabled()) {
            PermitAll permitAll = authorizationProperties.getPermitAll();
            if (permitAll.isActive()) {
                configurePermitAll(http, permitAll);
            }
            return http.authorizeExchange().anyExchange().authenticated().and();
        }
        return http.authorizeExchange().anyExchange().permitAll().and();
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
            // check that active, empty patterns will be interpreted as permit all the method type (empty patterns vs varargs)
            if (httpMethodMatcher.isActive()) {
                http.authorizeExchange().pathMatchers(httpMethodMatcher.getVerb(), httpMethodMatcher.getPatternsAsArray()).permitAll();
            }
        }
    }
}
