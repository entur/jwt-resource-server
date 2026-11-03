package org.entur.jwt.junit5.configuration.enrich;

import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.impl.MyAuthorizationServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.parallel.ResourceLocksProvider;
import org.junit.jupiter.api.parallel.ResourceLocksProvider.Lock;
import org.junit.jupiter.api.parallel.Resources;
import org.junit.platform.commons.support.AnnotationSupport;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The system-properties enricher sets (and clears) JVM-wide system properties, so test classes using it must not run in parallel.
 */
public class SystemPropertiesResourceLocksProviderTest {

    private static final Lock SYSTEM_PROPERTIES_LOCK = new Lock(Resources.SYSTEM_PROPERTIES, ResourceAccessMode.READ_WRITE);

    @AuthorizationServer("a")
    static class WithAuthorizationServer {
    }

    @MyAuthorizationServer
    static class WithComposedAuthorizationServer {
    }

    @AuthorizationServer("a")
    static class WithEnclosingAuthorizationServer {
        @AuthorizationServer("b")
        class Nested {
        }
    }

    private ClassLoader contextClassLoader;
    private URLClassLoader registeringClassLoader;

    @BeforeEach
    public void setUp() {
        contextClassLoader = Thread.currentThread().getContextClassLoader();
    }

    @AfterEach
    public void tearDown() throws IOException {
        Thread.currentThread().setContextClassLoader(contextClassLoader);
        if (registeringClassLoader != null) {
            registeringClassLoader.close();
        }
    }

    // in addition to the enrichers registered for the tests of this module
    private void registerEnricher(Path directory, Class<? extends ResourceServerConfigurationEnricher> enricher) throws IOException {
        Path services = Files.createDirectories(directory.resolve("META-INF").resolve("services"));
        Files.writeString(services.resolve(ResourceServerConfigurationEnricher.class.getName()), enricher.getName());

        registeringClassLoader = new URLClassLoader(new URL[] { directory.toUri().toURL() }, contextClassLoader);
        Thread.currentThread().setContextClassLoader(registeringClassLoader);
    }

    // as JUnit does it, i.e. also for composed annotations
    private static Set<Lock> getLocks(Class<?> testClass) throws ReflectiveOperationException {
        Set<Lock> locks = new HashSet<>();
        for (ResourceLock annotation : AnnotationSupport.findRepeatableAnnotations(testClass, ResourceLock.class)) {
            for (Class<? extends ResourceLocksProvider> provider : annotation.providers()) {
                locks.addAll(provider.getDeclaredConstructor().newInstance().provideForClass(testClass));
            }
        }
        return locks;
    }

    @Test
    public void testTestClassesUsingSystemPropertiesDoNotRunInParallel(@TempDir Path directory) throws Exception {
        registerEnricher(directory, SystemPropertiesResourceServerConfigurationEnricher.class);

        assertTrue(getLocks(WithAuthorizationServer.class).contains(SYSTEM_PROPERTIES_LOCK));
        assertTrue(getLocks(WithComposedAuthorizationServer.class).contains(SYSTEM_PROPERTIES_LOCK));
    }

    @Test
    public void testNestedTestClassesUsingSystemPropertiesDoNotRunInParallel(@TempDir Path directory) throws Exception {
        registerEnricher(directory, SystemPropertiesResourceServerConfigurationEnricher.class);

        Set<Lock> locks = new SystemPropertiesResourceLocksProvider().provideForNestedClass(List.of(WithEnclosingAuthorizationServer.class), WithEnclosingAuthorizationServer.Nested.class);
        assertEquals(Set.of(SYSTEM_PROPERTIES_LOCK), locks);
    }

    @Test
    public void testTestClassesNotUsingSystemPropertiesAreNotLocked() throws Exception {
        // only the properties file enricher is registered for the tests of this module
        assertFalse(getLocks(WithAuthorizationServer.class).contains(SYSTEM_PROPERTIES_LOCK));
        assertEquals(1, getLocks(WithAuthorizationServer.class).size());

        assertTrue(new SystemPropertiesResourceLocksProvider().provideForClass(WithAuthorizationServer.class).isEmpty());
        assertTrue(new SystemPropertiesResourceLocksProvider().provideForNestedClass(List.of(WithEnclosingAuthorizationServer.class), WithEnclosingAuthorizationServer.Nested.class).isEmpty());
    }
}
