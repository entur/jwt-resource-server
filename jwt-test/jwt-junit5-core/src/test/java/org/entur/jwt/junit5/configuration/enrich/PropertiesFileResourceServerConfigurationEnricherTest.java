package org.entur.jwt.junit5.configuration.enrich;

import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementation;
import org.entur.jwt.junit5.impl.AuthorizationServerImplementationFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Stream;

import static com.google.common.truth.Truth.assertThat;

public class PropertiesFileResourceServerConfigurationEnricherTest {

    private static final String LOCATION = "entur.jwt.tenants.concurrent.jwk.location";

    @AuthorizationServer("concurrent")
    static class ConcurrentTest {
    }

    private static Properties load(Path path) throws Exception {
        Properties properties = new Properties();
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        return properties;
    }

    @Test
    public void testPropertiesFileIsCompleteWhenWrittenConcurrently(@TempDir Path directory) throws Exception {
        List<AuthorizationServerImplementation> implementations = new AuthorizationServerImplementationFactory().create(ConcurrentTest.class);
        Path output = directory.resolve("jwt.junit5.properties");

        PropertiesFileResourceServerConfigurationEnricher enricher = new PropertiesFileResourceServerConfigurationEnricher("entur.jwt.tenants", output);
        enricher.beforeAll(implementations, null);

        String location = load(output).getProperty(LOCATION);
        assertThat(location).isNotNull();

        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < 4; i++) {
                futures.add(executor.submit(() -> {
                    for (int k = 0; k < 250; k++) {
                        enricher.beforeAll(implementations, null);
                    }
                    return null;
                }));
                futures.add(executor.submit(() -> {
                    for (int k = 0; k < 250; k++) {
                        assertThat(load(output).getProperty(LOCATION)).isEqualTo(location);
                    }
                    return null;
                }));
            }
            for (Future<?> future : futures) {
                future.get();
            }
        } finally {
            executor.shutdownNow();
        }

        // no temporary files left behind
        try (Stream<Path> files = Files.list(directory)) {
            assertThat(files.toList()).containsExactly(output);
        }
    }
}
