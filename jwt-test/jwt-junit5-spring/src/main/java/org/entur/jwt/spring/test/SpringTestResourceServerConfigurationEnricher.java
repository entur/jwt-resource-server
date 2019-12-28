package org.entur.jwt.spring.test;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.entur.jwt.junit5.configuration.enrich.PropertiesFileResourceServerConfigurationEnricher;
import org.entur.jwt.junit5.extention.AuthorizationServerExtension;
import org.entur.jwt.junit5.extention.AuthorizationServerTestContext;
import org.entur.jwt.junit5.extention.AuthorizationServerTestManager;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext.Namespace;
import org.junit.jupiter.api.extension.ExtensionContext.Store;
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

    private static boolean canCheckForApplicationContext;
    
    static {
        try {
            Method method = TestContext.class.getMethod("hasApplicationContext");
            canCheckForApplicationContext = method != null;
        } catch (Exception e) {
            canCheckForApplicationContext = false;
        }
    }
    
    
    private static final Log logger = LogFactory.getLog(SpringTestResourceServerConfigurationEnricher.class);

    /**
     * {@link Namespace} in which {@code TestContextManagers} are stored, keyed by
     * test class.
     */
    private static final Namespace SPRING_EXTENTION_NAMESPACE = Namespace.create(SpringExtension.class);

    public SpringTestResourceServerConfigurationEnricher() throws IOException {
        super();
    }

    @Override
    public void beforeAll(List<AuthorizationServerImplementation> authorizationServers, ExtensionContext context) throws IOException {
        TestContextManager testContextManager = getSpringTestContextManager(context);
        
        TestContext testContext = testContextManager.getTestContext(); // note: loads test context, but not main context
        if(canCheckForApplicationContext) {
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
                        testContext.markApplicationContextDirty(HierarchyMode.EXHAUSTIVE);
                        testContext.setAttribute(DependencyInjectionTestExecutionListener.REINJECT_DEPENDENCIES_ATTRIBUTE, Boolean.TRUE);
                    }
                    
                }
                super.beforeAll(authorizationServers, context);

                for (AuthorizationServerImplementation impl : authorizationServers) {
                    jwtTestContext.add(impl);
                }
            } else {
                jwtTestContextManager.setTestContext(new AuthorizationServerTestContext(authorizationServers));
    
                super.beforeAll(authorizationServers, context);
            }
        } else {
            super.beforeAll(authorizationServers, context);
            
            // see DirtiesContextBeforeModesTestExecutionListener and
            // DirtiesContextTestExecutionListener
            testContext.markApplicationContextDirty(HierarchyMode.EXHAUSTIVE);
            testContext.setAttribute(DependencyInjectionTestExecutionListener.REINJECT_DEPENDENCIES_ATTRIBUTE, Boolean.TRUE);
        }
    }

    private boolean canReuse(List<AuthorizationServerImplementation> authorizationServers, AuthorizationServerTestContext jwtTestContext, ConfigurableEnvironment environment, JwtEnvironmentResourceServerConfiguration config) {
        Map<String, String> currentlyConfigured = config.extractEnabledProperty(environment.getPropertySources(), ".jwk.location");
        Map<String, String> desiredConfigured = getRequired(authorizationServers);
        
        boolean reuse;
        if(currentlyConfigured.keySet().containsAll(desiredConfigured.keySet())) {
            reuse = true;
            
            // reconfigure current mock servers to have the correct certificates
            reconfigure: 
            for (AuthorizationServerImplementation impl : authorizationServers) {
                String configured = currentlyConfigured.get(impl.getId());
                
                for (AuthorizationServerImplementation candidate : jwtTestContext.getAuthorizationServers(impl)) {
                    // check for matches using filename convention; TODO improve matching by comparing content
                    if(configured.contains(Integer.toString(candidate.getJsonWebKeys().hashCode()))) {
                        impl.setEncoder(candidate.getEncoder());
                        
                        continue reconfigure;
                    }
                }
                reuse = false;
                
                break;
            }
            
        } else {
            reuse = false;
        }
        return reuse;
    }

    private Map<String, String> getRequired(List<AuthorizationServerImplementation> authorizationServers) {
        Map<String, String> props = new HashMap<>();
        for (AuthorizationServerImplementation authorizationServerImplementation : authorizationServers) {
            props.put(authorizationServerImplementation.getId(), "entur.jwt.tenants." + authorizationServerImplementation.getId() + ".jwk.location");
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
