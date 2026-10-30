package org.entur.jwt.junit5.configuration.enrich;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.configuration.resolve.PropertiesAuthorizationServerConfiguration;
import org.entur.jwt.junit5.extention.AuthorizationServerExtension;
import org.entur.jwt.junit5.impl.DefaultAuthorizationServerEncoder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The properties file is shared by test classes.
 */

public class PropertiesFileResourceServerConfigurationEnricherTest {

    private static final String PREFIX = "entur.jwt.tenants";

    public static class OtherAuthorizationServerEncoder extends DefaultAuthorizationServerEncoder {
    }

    @AuthorizationServer("a")
    static class TenantA {
    }

    @AuthorizationServer("b")
    static class TenantB {
    }

    // same id as TenantA, but other keys
    @AuthorizationServer(value = "a", encoder = OtherAuthorizationServerEncoder.class)
    static class OtherTenantA {
    }

    @AuthorizationServer
    static class Unnamed {
    }

    @AuthorizationServer("mock")
    static class NamedMock {
    }

    @AuthorizationServer("café")
    static class NonAscii {
    }

    @TempDir
    private Path directory;

    @Test
    public void testOtherTestClassReplacesFile() throws Exception {
        Path output = directory.resolve("jwt.junit5.properties");

        write(output, TenantA.class, TenantA.class);
        write(output, TenantB.class, TenantB.class);

        // a test class only sees its own authorization servers
        Properties properties = load(output);
        assertNull(properties.getProperty(PREFIX + ".a.issuer"));
        assertNull(properties.getProperty(PREFIX + ".a.jwk.location"));
        assertEquals("https://mock.issuer.b.xyz", properties.getProperty(PREFIX + ".b.issuer"));
        assertNotNull(properties.getProperty(PREFIX + ".b.jwk.location"));
    }

    @Test
    public void testNestedTestClassesAddAuthorizationServers() throws Exception {
        Path output = directory.resolve("jwt.junit5.properties");

        // i.e. TenantB is a @Nested test class of TenantA
        write(output, TenantA.class, TenantA.class);
        write(output, TenantB.class, TenantA.class);

        Properties properties = load(output);
        assertEquals("https://mock.issuer.a.xyz", properties.getProperty(PREFIX + ".a.issuer"));
        assertEquals("https://mock.issuer.b.xyz", properties.getProperty(PREFIX + ".b.issuer"));
    }

    @Test
    public void testPublishesTheKeysOfAuthorizationServersWithTheSameIdAtTheSameLocation() throws Exception {
        Path output = directory.resolve("jwt.junit5.properties");

        // i.e. OtherTenantA is a @Nested test class which overrides authorization server 'a'
        write(output, TenantA.class, TenantA.class);
        String location = load(output).getProperty(PREFIX + ".a.jwk.location");
        write(output, OtherTenantA.class, TenantA.class);

        // so that a resource server which reloads the keys gets the keys of the @Nested test class
        assertEquals(location, load(output).getProperty(PREFIX + ".a.jwk.location"));

        JWKSet published = JWKSet.parse(Files.readString(Paths.get(URI.create(location))));
        for (Class<?> testClass : List.of(TenantA.class, OtherTenantA.class)) {
            for (JWK key : JWKSet.parse(AuthorizationServerExtension.getFactory().create(testClass).get(0).getJsonWebKeys()).getKeys()) {
                assertNotNull(published.getKeyByKeyId(key.getKeyID()));
            }
        }
    }

    @Test
    public void testRejectsConflictingIssuers() throws Exception {
        Path output = directory.resolve("jwt.junit5.properties");

        // an authorization server without id, and one with id 'mock', within the same test class hierarchy
        write(output, Unnamed.class, Unnamed.class);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> write(output, NamedMock.class, Unnamed.class));
        assertFalse(e.getMessage().isEmpty());
    }

    @Test
    public void testNonAsciiTenantId() throws Exception {
        Path output = directory.resolve("jwt.junit5.properties");

        write(output, NonAscii.class, NonAscii.class);

        PropertiesAuthorizationServerConfiguration configuration = new PropertiesAuthorizationServerConfiguration(PREFIX, load(output));
        assertEquals("https://mock.issuer.café.xyz", configuration.getProperty("café", "issuer"));
        assertNotNull(JWKSet.parse(Files.readString(Paths.get(URI.create(configuration.getProperty("café", "jwk.location"))))));
    }

    @Test
    public void testConcurrentNestedTestClasses() throws Exception {
        Path output = directory.resolve("jwt.junit5.properties");

        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < 200; i++) {
                Class<?> testClass = i % 2 == 0 ? TenantA.class : TenantB.class;
                futures.add(executor.submit(() -> {
                    // i.e. @Nested test classes of the same top-level test class, running in parallel
                    write(output, testClass, TenantA.class);
                    // the file is always complete
                    Properties properties = load(output);
                    assertNotNull(properties.getProperty(PREFIX + "." + testClass.getAnnotation(AuthorizationServer.class).value() + ".issuer"));
                    return null;
                }));
            }
            for (Future<?> future : futures) {
                future.get(30, TimeUnit.SECONDS);
            }
        } finally {
            executor.shutdownNow();
        }

        Properties properties = load(output);
        assertNotNull(properties.getProperty(PREFIX + ".a.issuer"));
        assertNotNull(properties.getProperty(PREFIX + ".b.issuer"));
    }

    @Test
    public void testTestClassesUsingThePropertiesFileDoNotRunInParallel() {
        // the enricher is registered for the tests of this module
        assertFalse(new PropertiesFileResourceLocksProvider().provideForClass(TenantA.class).isEmpty());
    }

    private static void write(Path output, Class<?> testClass, Class<?> topLevelTestClass) throws IOException {
        PropertiesFileResourceServerConfigurationEnricher enricher = new PropertiesFileResourceServerConfigurationEnricher(PREFIX, output);
        enricher.write(AuthorizationServerExtension.getFactory().create(testClass), topLevelTestClass);
    }

    private static Properties load(Path output) throws IOException {
        Properties properties = new Properties();
        try (InputStream in = Files.newInputStream(output)) {
            properties.load(in);
        }
        return properties;
    }
}
