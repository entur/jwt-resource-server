package org.entur.jwt.spring.config;

import org.entur.jwt.spring.auth0.properties.AuthorizationProperties;
import org.entur.jwt.spring.auth0.properties.HttpMethodMatcher;
import org.entur.jwt.spring.auth0.properties.MatcherConfiguration;
import org.entur.jwt.spring.auth0.properties.PermitAll;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Default authorization. Extracted into its own class to allow for customization / override.
 */

public abstract class AuthorizationWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    private static Logger log = LoggerFactory.getLogger(AuthorizationWebSecurityConfigurerAdapter.class);

    protected final AuthorizationProperties authorizationProperties;

    @Autowired
    public AuthorizationWebSecurityConfigurerAdapter(AuthorizationProperties authorizationProperties) {
        this.authorizationProperties = authorizationProperties;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        // implementation note: this filter runs before the dispatcher servlet, and so
        // is out of reach of any ControllerAdvice
        log.info("Configure authorization filter");
        if (authorizationProperties.isEnabled()) {
            PermitAll permitAll = authorizationProperties.getPermitAll();
            if (permitAll.isActive()) {
                configurePermitAll(http, permitAll);
            }
            http.authorizeRequests().anyRequest().fullyAuthenticated();
        }
    }

    protected void configurePermitAll(HttpSecurity http, PermitAll permitAll) throws Exception {

        MatcherConfiguration mvcMatchers = permitAll.getMvcMatcher();
        if (mvcMatchers.isActive()) {
            configurePermitAllMvcMatchers(http, mvcMatchers);
        }

        MatcherConfiguration antMatchers = permitAll.getAntMatcher();
        if (antMatchers.isActive()) {
            configurePermitAllAntMatchers(http, antMatchers);
        }
    }

    protected void configurePermitAllAntMatchers(HttpSecurity http, MatcherConfiguration antMatchers)
            throws Exception {
        if (antMatchers.hasPatterns()) {
            // for all methods
            http.authorizeRequests().antMatchers(antMatchers.getPatternsAsArray()).permitAll();
        }

        // for specific methods
        for (HttpMethodMatcher httpMethodMatcher : antMatchers.getMethod().getActiveMethods()) {
            // check that active, empty patterns will be interpreted as permit all of the method type (empty patterns vs varargs)
            if (httpMethodMatcher.isActive()) {
                http.authorizeRequests().antMatchers(httpMethodMatcher.getVerb(), httpMethodMatcher.getPatternsAsArray()).permitAll();
            }
        }
    }

    protected void configurePermitAllMvcMatchers(HttpSecurity http, MatcherConfiguration mvcMatchers)
            throws Exception {
        if (mvcMatchers.hasPatterns()) {
            // for all methods
            http.authorizeRequests().mvcMatchers(mvcMatchers.getPatternsAsArray()).permitAll();
        }

        // for specific methods
        for (HttpMethodMatcher httpMethodMatcher : mvcMatchers.getMethod().getActiveMethods()) {
            // check that active, empty patterns will be interpreted as permit all of the method type (empty patterns vs varargs)
            if (httpMethodMatcher.isActive()) {
                http.authorizeRequests().mvcMatchers(httpMethodMatcher.getVerb(), httpMethodMatcher.getPatternsAsArray()).permitAll();
            }
        }
    }
}