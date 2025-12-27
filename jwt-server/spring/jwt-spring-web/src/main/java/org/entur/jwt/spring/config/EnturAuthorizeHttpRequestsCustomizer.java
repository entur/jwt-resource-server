package org.entur.jwt.spring.config;

import org.entur.jwt.spring.properties.AuthorizationProperties;
import org.entur.jwt.spring.properties.CustomHttpMethod;
import org.entur.jwt.spring.properties.HttpMethodMatcher;
import org.entur.jwt.spring.properties.MatcherConfiguration;
import org.entur.jwt.spring.properties.PermitAll;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;

/**
 * Default authorization. Extracted into its own class to allow for customization / override.
 */

public class EnturAuthorizeHttpRequestsCustomizer implements Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry> {

    private static Logger LOGGER = LoggerFactory.getLogger(EnturAuthorizeHttpRequestsCustomizer.class);

    private final AuthorizationProperties authorizationProperties;

    public EnturAuthorizeHttpRequestsCustomizer(AuthorizationProperties authorizationProperties) {
        this.authorizationProperties = authorizationProperties;
    }

    @Override
    public void customize(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) {
        if(LOGGER.isDebugEnabled()) LOGGER.debug("Configure authorization filter");
        if (authorizationProperties.isEnabled()) {
            PermitAll permitAll = authorizationProperties.getPermitAll();
            if (permitAll.isActive()) {
                configurePermitAll(registry, permitAll);
            }
            registry.anyRequest().fullyAuthenticated();
        }
    }

    protected void configurePermitAll(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry, PermitAll permitAll) {
        MatcherConfiguration matchers = permitAll.getMatcher();
        if (matchers.isActive()) {
            configurePermitAllMatchers(registry, matchers);
        }
    }

    protected void configurePermitAllMatchers(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry, MatcherConfiguration matchers) {
        if (matchers.hasPatterns()) {
            // for all methods
            String[] patternsAsArray = matchers.getPatternsAsArray();

            CustomHttpMethod type = matchers.getType();

            for(String pattern : patternsAsArray) {
                processPattern(type, pattern, registry, null);
            }
        }

        // for specific methods
        for (HttpMethodMatcher httpMethodMatcher : matchers.getMethod().getActiveMethods()) {
            // check that active, empty patterns will be interpreted as permit all of the method type (empty patterns vs varargs)
            if (httpMethodMatcher.isActive()) {

                CustomHttpMethod type = httpMethodMatcher.getType() == null ? matchers.getType() : httpMethodMatcher.getType();

                String[] patternsAsArray = httpMethodMatcher.getPatternsAsArray();
                for(String pattern : patternsAsArray) {
                    processPattern(type, pattern, registry, httpMethodMatcher.getVerb());
                }
            }
        }
    }

    protected void processPattern(CustomHttpMethod type, String pattern, AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry, HttpMethod verb) {
        switch (type) {
            case DEFAULT:
                registry.requestMatchers(verb, pattern).permitAll();
                break;
            default:
                throw new IllegalArgumentException("Unknown matcher type '" + type + "'.");
        }
        LOGGER.debug("Permit all for " + pattern + " " + verb);
    }

}