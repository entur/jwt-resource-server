package org.entur.jwt.spring.test;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.entur.jwt.junit5.configuration.enrich.PropertiesFileResourceServerConfigurationEnricher;
import org.entur.jwt.junit5.extention.AuthorizationServerExtension;
import org.entur.jwt.junit5.extention.AuthorizationServerTestContext;
import org.entur.jwt.junit5.extention.AuthorizationServerTestManager;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext.Namespace;
import org.junit.jupiter.api.extension.ExtensionContext.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.test.annotation.DirtiesContext.HierarchyMode;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.TestContextManager;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;
import org.springframework.util.Assert;

// https://docs.spring.io/spring/docs/current/spring-framework-reference/testing.html#testcontext-ctx-management

public class SpringTestResourceServerConfigurationEnricher extends PropertiesFileResourceServerConfigurationEnricher {

    /**
     * {@link Namespace} in which {@code TestContextManagers} are stored, keyed by
     * test class.
     */
    private static final Namespace SPRING_EXTENTION_NAMESPACE = Namespace.create(SpringExtension.class);

    private static Logger LOGGER = LoggerFactory.getLogger(SpringTestResourceServerConfigurationEnricher.class);

    public SpringTestResourceServerConfigurationEnricher() throws IOException {
        super();
    }

    @Override
    public void beforeAll(List<AuthorizationServerImplementation> authorizationServers, ExtensionContext context) throws IOException {
        TestContextManager testContextManager = getSpringTestContextManager(context);
        
        TestContext testContext = testContextManager.getTestContext(); // note: loads test context, but not main context
        AuthorizationServerTestManager jwtTestContextManager = getJwtTestContextManager(context);
        AuthorizationServerTestContext jwtTestContext = jwtTestContextManager.getTestContext();

        if(jwtTestContext != null) {
            if(testContext.hasApplicationContext()) { // Spring 2.2. method
                // try to reuse the spring context
                // note that the spring context caches multiple contexts
                // so the last authorization states are not necessarily the right ones
                // check if all our authorization servers were already loaded into the context

                // compare the configured with the required mocks
                ApplicationContext applicationContext = testContext.getApplicationContext();

                ConfigurableEnvironment environment = (ConfigurableEnvironment) applicationContext.getEnvironment();

                JwtEnvironmentResourceServerConfiguration config = new JwtEnvironmentResourceServerConfiguration(environment, "entur.jwt.tenants", ".enabled");

                // note: the context might be marked dirty already
                if(!canReuse(authorizationServers, jwtTestContext, environment, config)) {
                    // see DirtiesContextBeforeModesTestExecutionListener and
                    // DirtiesContextTestExecutionListener
                    if(LOGGER.isTraceEnabled()) LOGGER.trace("Mark context dirty");

                    testContext.markApplicationContextDirty(HierarchyMode.EXHAUSTIVE);
                    testContext.setAttribute(DependencyInjectionTestExecutionListener.REINJECT_DEPENDENCIES_ATTRIBUTE, Boolean.TRUE);
                }

            }
            super.beforeAll(authorizationServers, context);

            for (AuthorizationServerImplementation impl : authorizationServers) {
                jwtTestContext.add(impl);
            }
        } else {
            if(LOGGER.isTraceEnabled()) LOGGER.trace("Cannot reuse context, not present");

            jwtTestContextManager.setTestContext(new AuthorizationServerTestContext(authorizationServers));

            super.beforeAll(authorizationServers, context);
        }
    }

    private boolean canReuse(List<AuthorizationServerImplementation> authorizationServers, AuthorizationServerTestContext jwtTestContext, ConfigurableEnvironment environment, JwtEnvironmentResourceServerConfiguration config) {
        Map<String, String> currentlyConfigured = config.extractEnabledProperty(environment.getPropertySources(), ".jwk.location");
        Map<String, String> desiredConfigured = getRequired(authorizationServers);

        if(!currentlyConfigured.keySet().containsAll(desiredConfigured.values())) {
            if(LOGGER.isTraceEnabled()) LOGGER.trace("Cannot reuse context, wanted " + desiredConfigured + ", only had " + currentlyConfigured + " for " + currentlyConfigured.size());
            return false;
        }

        // reconfigure current mock servers to have the correct certificates
        reconfigure:
        for (AuthorizationServerImplementation impl : authorizationServers) {

            String id = impl.getId();
            if(id.isEmpty()) {
                id = "mock";
            }
            String configured = desiredConfigured.get(id);

            // JWKs file currently configured in spring properties for the current authorization server
            String propertyValue = currentlyConfigured.get(configured);

            // check to see whether we already have the keys
            // if so, reconfigure the current authorization server keys to match the existing property
            List<AuthorizationServerImplementation> candidates = jwtTestContext.getAuthorizationServers(impl);
            for(int i = 0; i < candidates.size(); i++) {
                AuthorizationServerImplementation candidate = candidates.get(i);
                // check for matches using filename convention; TODO improve matching by comparing content
                if (propertyValue.contains(Integer.toString(candidate.getJsonWebKeys().hashCode())) && candidate == impl) {
                    if (LOGGER.isTraceEnabled())
                        LOGGER.trace("Found JWKs in candidate " +  (i + 1 ) + "/" + candidates.size() + " for " + id);

                    continue reconfigure;
                } else {
                    if (LOGGER.isTraceEnabled())
                        LOGGER.trace("Could not match JWKs (" + Integer.toString(candidate.getJsonWebKeys().hashCode()) + ") in candidate " +  (i + 1 ) + "/" + candidates.size() + " for " + id);
                }
            }

            if(LOGGER.isTraceEnabled()) LOGGER.trace("Cannot reuse context, could not find JWKs for " + id + " at " + propertyValue + ", no matching JWKs in " + candidates.size() + " candidates.");

            return false;
        }
        return true;
    }

    private Map<String, String> getRequired(List<AuthorizationServerImplementation> authorizationServers) {
        Map<String, String> props = new HashMap<>();
        for (AuthorizationServerImplementation authorizationServerImplementation : authorizationServers) {
            String id = authorizationServerImplementation.getId();
            if(id.isEmpty()) {
                id = "mock";
            }
            props.put(id, "entur.jwt.tenants." + id + ".jwk.location");
        }
        
        return props;
    }


    /**
     * Get the {@link TestContextManager} associated with the supplied
     * {@code ExtensionContext}.
     * 
     * @return the {@code TestContextManager} (never {@code null})
     */
    private static TestContextManager getSpringTestContextManager(ExtensionContext context) {
        Assert.notNull(context, "ExtensionContext must not be null");
        Class<?> testClass = context.getRequiredTestClass();
        Store store = getSpringStore(context);
        return store.getOrComputeIfAbsent(testClass, TestContextManager::new, TestContextManager.class);
    }

    protected static Store getSpringStore(ExtensionContext context) {
        return context.getRoot().getStore(SPRING_EXTENTION_NAMESPACE);
    }

    /**
     * Get the {@link TestContextManager} associated with the supplied
     * {@code ExtensionContext}.
     * 
     * @return the {@code TestContextManager} (never {@code null})
     */
    private static AuthorizationServerTestManager getJwtTestContextManager(ExtensionContext context) {
        Store store = AuthorizationServerExtension.getStore(context);
        return store.getOrComputeIfAbsent(AuthorizationServerTestManager.class);
    }
}
