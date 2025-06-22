package org.entur.jwt.spring.test;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.entur.jwt.junit5.configuration.enrich.AbstractPropertiesResourceServerConfigurationEnricher;
import org.entur.jwt.junit5.configuration.resolve.ResourceServerConfiguration;
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

public class SpringTestResourceServerConfigurationEnricher extends AbstractPropertiesResourceServerConfigurationEnricher {

    private static final Log logger = LogFactory.getLog(SpringTestResourceServerConfigurationEnricher.class);

    public SpringTestResourceServerConfigurationEnricher() throws IOException {
        super();
    }

    @Override
    public void beforeAll(List<AuthorizationServerImplementation> authorizationServers, ExtensionContext context) throws IOException {
        logger.info("beforeAll on thread    " + Thread.currentThread().getName());
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

    @Override
    public void beforeEach(ResourceServerConfiguration configuration, ExtensionContext context) {
        // do nothing
    }

    @Override
    public void afterAll(ExtensionContext context) throws IOException {
        // do nothing
    }
}
