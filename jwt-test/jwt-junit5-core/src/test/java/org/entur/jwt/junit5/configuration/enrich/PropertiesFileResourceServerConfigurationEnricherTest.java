package org.entur.jwt.junit5.configuration.enrich;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.entur.jwt.junit5.AuthorizationServer;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * The properties file is shared by test classes, which might run in parallel.
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

    @TempDir
    private Path directory;

    @Test
    public void testAddsAuthorizationServersOfLaterTestClasses() throws Exception {
        Path output = directory.resolve("jwt.junit5.properties");
        // i.e. from a previous run
        Files.writeString(output, PREFIX + ".stale.issuer=https://stale\n");

        write(output, TenantA.class);
        write(output, TenantB.class);

        Properties properties = load(output);
        // the first test class in this JVM replaces the file
        assertNull(properties.getProperty(PREFIX + ".stale.issuer"));
        assertEquals("https://mock.issuer.a.xyz", properties.getProperty(PREFIX + ".a.issuer"));
        assertEquals("https://mock.issuer.b.xyz", properties.getProperty(PREFIX + ".b.issuer"));
        assertNotNull(properties.getProperty(PREFIX + ".a.jwk.location"));
        assertNotNull(properties.getProperty(PREFIX + ".b.jwk.location"));
    }

    @Test
    public void testPublishesTheKeysOfAuthorizationServersWithTheSameId() throws Exception {
        Path output = directory.resolve("jwt.junit5.properties");

        write(output, TenantA.class);
        write(output, OtherTenantA.class);

        JWKSet published = JWKSet.parse(Files.readString(Paths.get(URI.create(load(output).getProperty(PREFIX + ".a.jwk.location")))));
        for (Class<?> testClass : List.of(TenantA.class, OtherTenantA.class)) {
            for (JWK key : JWKSet.parse(AuthorizationServerExtension.getFactory().create(testClass).get(0).getJsonWebKeys()).getKeys()) {
                assertNotNull(published.getKeyByKeyId(key.getKeyID()));
            }
        }
    }

    @Test
    public void testConcurrentTestClasses() throws Exception {
        Path output = directory.resolve("jwt.junit5.properties");

        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < 200; i++) {
                Class<?> testClass = i % 2 == 0 ? TenantA.class : TenantB.class;
                futures.add(executor.submit(() -> {
                    write(output, testClass);
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

    private static void write(Path output, Class<?> testClass) throws IOException {
        PropertiesFileResourceServerConfigurationEnricher enricher = new PropertiesFileResourceServerConfigurationEnricher(PREFIX, output);
        enricher.beforeAll(AuthorizationServerExtension.getFactory().create(testClass), null);
    }

    private static Properties load(Path output) throws IOException {
        Properties properties = new Properties();
        try (InputStream in = Files.newInputStream(output)) {
            properties.load(in);
        }
        return properties;
    }
}
