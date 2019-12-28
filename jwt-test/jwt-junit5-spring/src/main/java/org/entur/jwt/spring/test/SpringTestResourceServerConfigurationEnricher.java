package org.entur.jwt.spring.test;

import java.io.IOException;
import java.lang.reflect.Method;
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
        AuthorizationServerTestManager jwtTestContextManager = getJwtTestContextManager(context);

        TestContextManager testContextManager = getSpringTestContextManager(context);
        
        TestContext testContext = testContextManager.getTestContext(); // note: loads test context, but not main context
        if(canCheckForApplicationContext) {
            if(testContext.hasApplicationContext()) { // Spring 2.2. method
                // try to reuse the spring context
                // note that the spring context caches multiple contexts
                // so the last authorization states are not necessarily the right
                // check if all our authorization servers were already loaded into the context
    
                // compare the configured with the required mocks
                ApplicationContext applicationContext = testContext.getApplicationContext();
                
                AuthorizationServerTestContext jwtTestContext = jwtTestContextManager.getTestContext();
                
                ConfigurableEnvironment environment = (ConfigurableEnvironment) applicationContext.getEnvironment();
                
                JwtEnvironmentResourceServerConfiguration config = new JwtEnvironmentResourceServerConfiguration(environment, "entur.jwt.tenants", ".enabled");
                
                boolean dirty = checkDirty(authorizationServers, jwtTestContext, environment, config);
                
                super.beforeAll(authorizationServers, context); // might be dirty regardless
    
                if(dirty) {
                    // see DirtiesContextBeforeModesTestExecutionListener and
                    // DirtiesContextTestExecutionListener
                    testContext.markApplicationContextDirty(HierarchyMode.EXHAUSTIVE);
                    testContext.setAttribute(DependencyInjectionTestExecutionListener.REINJECT_DEPENDENCIES_ATTRIBUTE, Boolean.TRUE);
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

    private boolean checkDirty(List<AuthorizationServerImplementation> authorizationServers, AuthorizationServerTestContext jwtTestContext, ConfigurableEnvironment environment, JwtEnvironmentResourceServerConfiguration config) {
        Map<String, String> extractEnabled = config.extractEnabled(environment.getPropertySources(), ".jwk.location");
        
        boolean dirty;
        if(containsAll(authorizationServers, extractEnabled)) {
            dirty = false;
            
            // reconfigure current mock servers to have the correct certificates
            for (AuthorizationServerImplementation impl : authorizationServers) {
                String string = extractEnabled.get("entur.jwt.tenants." + impl.getId() + ".jwk.location");
                
                for (AuthorizationServerImplementation candidate : jwtTestContext.getAuthorizationServers(impl)) {
                    if(string.contains(Integer.toString(candidate.getJsonWebKeys().hashCode()))) {
                        impl.setEncoder(candidate.getEncoder());
                        break;
                    }
                }
            }
            
        } else {
            dirty = true;
        }
        return dirty;
    }

    private boolean containsAll(List<AuthorizationServerImplementation> authorizationServers, Map<String, String> extractEnabled) {
        for (AuthorizationServerImplementation authorizationServerImplementation : authorizationServers) {
            if(!extractEnabled.containsKey("entur.jwt.tenants." + authorizationServerImplementation.getId() + ".jwk.location")) {
                return false;
            }
        }
        return true;
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
