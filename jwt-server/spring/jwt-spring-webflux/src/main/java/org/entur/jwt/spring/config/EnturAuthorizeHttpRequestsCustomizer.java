package org.entur.jwt.spring.config;

import org.entur.jwt.spring.properties.AuthorizationProperties;
import org.entur.jwt.spring.properties.HttpMethodMatcher;
import org.entur.jwt.spring.properties.MatcherConfiguration;
import org.entur.jwt.spring.properties.PermitAll;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;

/**
 * Default authorization. Extracted into its own class to allow for customization / override.
 */

public class EnturAuthorizeHttpRequestsCustomizer implements Customizer<ServerHttpSecurity.AuthorizeExchangeSpec> {

    private static Logger log = LoggerFactory.getLogger(EnturAuthorizeHttpRequestsCustomizer.class);

    private final AuthorizationProperties authorizationProperties;

    public EnturAuthorizeHttpRequestsCustomizer(AuthorizationProperties authorizationProperties) {
        this.authorizationProperties = authorizationProperties;
    }

    @Override
    public void customize(ServerHttpSecurity.AuthorizeExchangeSpec authorizeExchangeSpec) {
        log.info("Configure authorization filter");
        if (authorizationProperties.isEnabled()) {
            PermitAll permitAll = authorizationProperties.getPermitAll();
            if (permitAll.isActive()) {
                configurePermitAll(authorizeExchangeSpec, permitAll);
            }
            authorizeExchangeSpec.anyExchange().authenticated();
        }
    }

    protected void configurePermitAll(ServerHttpSecurity.AuthorizeExchangeSpec registry, PermitAll permitAll) {
        MatcherConfiguration mvcMatchers = permitAll.getMatcher();
        if (mvcMatchers.isActive()) {
            configurePermitAllMatchers(registry, mvcMatchers);
        }
    }

    protected void configurePermitAllMatchers(ServerHttpSecurity.AuthorizeExchangeSpec registry, MatcherConfiguration matchers) {
        if (matchers.hasPatterns()) {
            // for all methods
            String[] patternsAsArray = matchers.getPatternsAsArray();

            for (String pattern : patternsAsArray) {
                log.info("Permit all for " + pattern);
            }

            registry.pathMatchers(patternsAsArray).permitAll();
        }

        // for specific methods
        for (HttpMethodMatcher httpMethodMatcher : matchers.getMethod().getActiveMethods()) {
            // check that active, empty patterns will be interpreted as permit all of the method type (empty patterns vs varargs)
            if (httpMethodMatcher.isActive()) {
                String[] patternsAsArray = httpMethodMatcher.getPatternsAsArray();
                for (String pattern : patternsAsArray) {
                    log.info("Permit all " + httpMethodMatcher.getVerb() + " for " + pattern);
                }

                registry.pathMatchers(httpMethodMatcher.getVerb(), httpMethodMatcher.getPatternsAsArray()).permitAll();
            }
        }
    }


}