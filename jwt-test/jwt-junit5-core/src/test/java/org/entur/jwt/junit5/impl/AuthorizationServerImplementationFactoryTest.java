package org.entur.jwt.junit5.impl;

import com.nimbusds.jose.jwk.JWKSet;
import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static com.google.common.truth.Truth.assertThat;

public class AuthorizationServerImplementationFactoryTest {

    private static final String PREFIX = "entur.jwt.tenants";
    private static final String LOCATION = PREFIX + ".concurrent.jwk.location";

    @AuthorizationServer("concurrent")
    static class ConcurrentTest {
    }

    @Test
    public void testJsonWebKeysFileIsCompleteWhenGettingPropertiesConcurrently() throws Exception {
        List<AuthorizationServerImplementation> implementations = new AuthorizationServerImplementationFactory().create(ConcurrentTest.class);

        JWKSet expected = JWKSet.parse(implementations.get(0).getJsonWebKeys());
        String location = (String) AuthorizationServerImplementationFactory.getProperties(PREFIX, implementations).get(LOCATION);
        Path path = Paths.get(URI.create(location));

        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < 4; i++) {
                futures.add(executor.submit(() -> {
                    for (int k = 0; k < 250; k++) {
                        assertThat(AuthorizationServerImplementationFactory.getProperties(PREFIX, implementations).get(LOCATION)).isEqualTo(location);
                    }
                    return null;
                }));
                futures.add(executor.submit(() -> {
                    for (int k = 0; k < 250; k++) {
                        assertThat(JWKSet.parse(Files.readString(path)).getKeys()).isEqualTo(expected.getKeys());
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
    }
}
