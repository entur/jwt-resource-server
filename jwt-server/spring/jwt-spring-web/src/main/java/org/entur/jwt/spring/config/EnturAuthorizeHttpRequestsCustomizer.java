package org.entur.jwt.spring.config;

import org.entur.jwt.spring.auth0.properties.AuthorizationProperties;
import org.entur.jwt.spring.auth0.properties.HttpMethodMatcher;
import org.entur.jwt.spring.auth0.properties.MatcherConfiguration;
import org.entur.jwt.spring.auth0.properties.PermitAll;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;

/**
 * Default authorization. Extracted into its own class to allow for customization / override.
 */

public class EnturAuthorizeHttpRequestsCustomizer implements Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry> {

    private static Logger log = LoggerFactory.getLogger(EnturAuthorizeHttpRequestsCustomizer.class);

    private final AuthorizationProperties authorizationProperties;

    public EnturAuthorizeHttpRequestsCustomizer(AuthorizationProperties authorizationProperties) {
        this.authorizationProperties = authorizationProperties;
    }

    @Override
    public void customize(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) {
        log.info("Configure authorization filter");
        if (authorizationProperties.isEnabled()) {
            PermitAll permitAll = authorizationProperties.getPermitAll();
            if (permitAll.isActive()) {
                configurePermitAll(registry, permitAll);
            }
            registry.anyRequest().fullyAuthenticated();
        }
    }

    protected void configurePermitAll(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry, PermitAll permitAll) {
        MatcherConfiguration mvcMatchers = permitAll.getMatcher();
        if (mvcMatchers.isActive()) {
            configurePermitAllMatchers(registry, mvcMatchers);
        }
    }

    protected void configurePermitAllMatchers(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry, MatcherConfiguration matchers) {
        if (matchers.hasPatterns()) {
            // for all methods
            registry.requestMatchers(matchers.getPatternsAsArray()).permitAll();
        }

        // for specific methods
        for (HttpMethodMatcher httpMethodMatcher : matchers.getMethod().getActiveMethods()) {
            // check that active, empty patterns will be interpreted as permit all of the method type (empty patterns vs varargs)
            if (httpMethodMatcher.isActive()) {
                registry.requestMatchers(httpMethodMatcher.getVerb(), httpMethodMatcher.getPatternsAsArray()).permitAll();
            }
        }
    }

}