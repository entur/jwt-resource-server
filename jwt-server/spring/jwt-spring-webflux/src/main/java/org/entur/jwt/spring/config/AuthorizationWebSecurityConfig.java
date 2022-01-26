package org.entur.jwt.spring.config;

import org.entur.jwt.spring.auth0.properties.AuthorizationProperties;
import org.entur.jwt.spring.auth0.properties.HttpMethodMatcher;
import org.entur.jwt.spring.auth0.properties.MatcherConfiguration;
import org.entur.jwt.spring.auth0.properties.PermitAll;
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

        // TODO merge new vs old path syntax
        MatcherConfiguration mvcMatcher = permitAll.getMvcMatcher();
        if (mvcMatcher.isActive()) {
            throw new IllegalStateException("MVC matches are not supported, use ant matchers");
        }

        MatcherConfiguration antMatcher = permitAll.getAntMatcher();
        if (antMatcher.isActive()) {
            configurePermitAllAntMatchers(http, antMatcher);
        }
    }

    protected void configurePermitAllAntMatchers(ServerHttpSecurity http, MatcherConfiguration antMatchers) throws Exception {
        if (antMatchers.hasPatterns()) {
            // for all methods
            http.authorizeExchange().pathMatchers(antMatchers.getPatternsAsArray()).permitAll();
        }

        // for specific methods
        for (HttpMethodMatcher httpMethodMatcher : antMatchers.getMethod().getActiveMethods()) {
            // check that active, empty patterns will be interpreted as permit all the method type (empty patterns vs varargs)
            if (httpMethodMatcher.isActive()) {
                http.authorizeExchange().pathMatchers(httpMethodMatcher.getVerb(), httpMethodMatcher.getPatternsAsArray()).permitAll();
            }
        }
    }
}
