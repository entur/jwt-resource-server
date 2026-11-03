package org.entur.jwt.junit5.configuration.enrich;

import org.entur.jwt.junit5.extension.AuthorizationServerExtension;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ExtensionContext.Namespace;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolver;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * The authorization servers of a test class are stored per test class, so that {@literal @}Nested test classes
 * (or test classes running in parallel) do not overwrite or remove each other's.
 */
public class ExtensionContextStoreResourceServerConfigurationEnricherTest {

    private static final Namespace NAMESPACE = AuthorizationServerExtension.NAMESPACE;
    private static final String KEY = ExtensionContextStoreResourceServerConfigurationEnricher.KEY_AUTHORIZATION_SERVERS;

    // invokes the enricher for each test class, including the nested ones, as the authorization server extension does
    static class EnricherExtension implements BeforeAllCallback, AfterAllCallback, ParameterResolver {

        private final ExtensionContextStoreResourceServerConfigurationEnricher enricher = new ExtensionContextStoreResourceServerConfigurationEnricher();
        private final Map<Class<?>, List<AuthorizationServerImplementation>> servers = new ConcurrentHashMap<>();

        @Override
        public void beforeAll(ExtensionContext context) throws Exception {
            List<AuthorizationServerImplementation> testClassServers = new ArrayList<>();
            servers.put(context.getRequiredTestClass(), testClassServers);

            enricher.beforeAll(testClassServers, context);
        }

        @Override
        public void afterAll(ExtensionContext context) throws Exception {
            Object stored = context.getStore(NAMESPACE).get(KEY);
            assertNotNull(stored);

            enricher.afterAll(context);

            // gone, or the value of the enclosing test class
            assertNotSame(stored, context.getStore(NAMESPACE).get(KEY));
        }

        List<AuthorizationServerImplementation> getServers(Class<?> testClass) {
            return servers.get(testClass);
        }

        @Override
        public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
            return parameterContext.getParameter().getType() == ExtensionContext.class;
        }

        @Override
        public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
            return extensionContext;
        }
    }

    @RegisterExtension
    static EnricherExtension extension = new EnricherExtension();

    @Test
    public void testTestClassFindsItsOwnAuthorizationServers(ExtensionContext context) {
        assertSame(extension.getServers(ExtensionContextStoreResourceServerConfigurationEnricherTest.class), context.getStore(NAMESPACE).get(KEY));
    }

    @Nested
    class NestedTestClass {

        @Test
        public void testNestedTestClassFindsItsOwnAuthorizationServers(ExtensionContext context) {
            assertSame(extension.getServers(NestedTestClass.class), context.getStore(NAMESPACE).get(KEY));
            assertNotSame(extension.getServers(ExtensionContextStoreResourceServerConfigurationEnricherTest.class), context.getStore(NAMESPACE).get(KEY));
        }
    }

    // after the nested test class, but before the enricher cleans up for this test class
    @AfterAll
    static void verifyNestedTestClassDidNotRemoveAuthorizationServersOfEnclosingTestClass(ExtensionContext context) {
        assertSame(extension.getServers(ExtensionContextStoreResourceServerConfigurationEnricherTest.class), context.getStore(NAMESPACE).get(KEY));
    }
}
