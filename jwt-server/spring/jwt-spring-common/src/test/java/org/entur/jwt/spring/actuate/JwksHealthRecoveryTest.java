package org.entur.jwt.spring.actuate;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.sun.net.httpserver.HttpServer;
import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.JwkSourceMapFactory;
import org.entur.jwt.spring.properties.jwk.JwkLocationProperties;
import org.entur.jwt.spring.properties.jwk.JwkProperties;
import org.entur.jwt.spring.properties.jwk.JwtTenantProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Status;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests that the JWKs health recovers after a failed refresh while the JWK set is still cached,
 * i.e. a token with an unknown key id during a (short) outage of the JWKs endpoint.
 * The JWK source chain is built by {@link JwkSourceMapFactory} and served by a local HTTP server.
 */
class JwksHealthRecoveryTest {

    private static final String ISSUER = "https://issuer.example/";
    private static final String KEY_ID = "k1";

    private HttpServer server;
    private volatile boolean fail;
    private final AtomicInteger requests = new AtomicInteger();

    private ListJwksHealthIndicator healthIndicator;
    private JwkSourceMap jwkSourceMap;

    @BeforeEach
    void startServer() throws Exception {
        byte[] jwks = new JWKSet(new RSAKeyGenerator(2048).keyID(KEY_ID).generate().toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);

        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/jwks.json", exchange -> {
            requests.incrementAndGet();
            if (fail) {
                exchange.sendResponseHeaders(503, -1);
            } else {
                exchange.sendResponseHeaders(200, jwks.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(jwks);
                }
            }
            exchange.close();
        });
        server.start();

        healthIndicator = new ListJwksHealthIndicator(Executors.newSingleThreadExecutor(), "List");
    }

    @AfterEach
    void stopServer() throws IOException {
        if (jwkSourceMap != null) {
            jwkSourceMap.close();
        }
        healthIndicator.close();
        server.stop(0);
    }

    private JWKSource<SecurityContext> jwkSource(JwkProperties jwkProperties) {
        JwkLocationProperties location = new JwkLocationProperties();
        location.setLocation("http://" + server.getAddress().getHostString() + ":" + server.getAddress().getPort() + "/jwks.json");

        JwtTenantProperties tenant = new JwtTenantProperties();
        tenant.setIssuer(ISSUER);
        tenant.setJwk(location);

        jwkSourceMap = new JwkSourceMapFactory<>().getJwkSourceMap(Map.of("myTenant", tenant), jwkProperties, healthIndicator);

        return (JWKSource<SecurityContext>) jwkSourceMap.getJwkSources().get(ISSUER);
    }

    private static List<JWK> getKeys(JWKSource<SecurityContext> jwkSource, String keyId) throws KeySourceException {
        return jwkSource.get(new JWKSelector(new JWKMatcher.Builder().keyID(keyId).build()), null);
    }

    // unhealthy JWKs are refreshed in the background, wait for the refresh to complete
    private Status health() throws InterruptedException {
        Status status = healthIndicator.health().getStatus();

        long deadline = System.currentTimeMillis() + 10_000;
        while (!healthIndicator.isIdle()) {
            if (System.currentTimeMillis() > deadline) {
                throw new AssertionError("Timeout waiting for JWKs health refresh");
            }
            Thread.sleep(10);
        }
        return status;
    }

    @Test
    void recoversWithoutOutageCache() throws Exception {
        JwkProperties jwkProperties = new JwkProperties();
        jwkProperties.getRateLimit().setEnabled(false);
        jwkProperties.getOutageCache().setEnabled(false);

        assertRecoversAfterFailedRefresh(jwkSource(jwkProperties));
    }

    @Test
    void recoversWithExpiredOutageCache() throws Exception {
        JwkProperties jwkProperties = new JwkProperties();
        jwkProperties.getRateLimit().setEnabled(false);
        // shorter than the JWK set cache time to live
        jwkProperties.getOutageCache().setTimeToLive(1);

        JWKSource<SecurityContext> jwkSource = jwkSource(jwkProperties);
        assertEquals(1, getKeys(jwkSource, KEY_ID).size());

        // let the outage cache expire, while the JWK set is still cached
        Thread.sleep(1100);

        assertRecoversAfterFailedRefresh(jwkSource);
    }

    private void assertRecoversAfterFailedRefresh(JWKSource<SecurityContext> jwkSource) throws Exception {
        assertEquals(1, getKeys(jwkSource, KEY_ID).size());
        assertEquals(Status.UP, health());

        fail = true;

        // a token with an unknown key id refreshes the JWK set, which fails
        assertThrows(KeySourceException.class, () -> getKeys(jwkSource, "unknown"));
        // known keys are still served from the cache
        assertEquals(1, getKeys(jwkSource, KEY_ID).size());

        // health checks attempt to refresh the JWK set, which is still unavailable
        int requestsBeforeHealthChecks = requests.get();
        assertEquals(Status.DOWN, health());
        assertEquals(Status.DOWN, health());
        assertEquals(Status.DOWN, health());
        assertTrue(requests.get() > requestsBeforeHealthChecks);

        fail = false;

        // the refresh happens in the background
        assertEquals(Status.DOWN, health());
        assertEquals(Status.UP, health());
        assertEquals(Status.UP, health());

        assertEquals(1, getKeys(jwkSource, KEY_ID).size());
    }

    @Test
    void healthChecksRespectRateLimit() throws Exception {
        // default rate limit: at most one refresh per 10 seconds (plus one extra)
        JwkProperties jwkProperties = new JwkProperties();
        jwkProperties.getOutageCache().setEnabled(false);

        JWKSource<SecurityContext> jwkSource = jwkSource(jwkProperties);
        assertEquals(1, getKeys(jwkSource, KEY_ID).size());
        assertEquals(Status.UP, health());

        fail = true;
        assertThrows(KeySourceException.class, () -> getKeys(jwkSource, "unknown"));

        fail = false;

        // health checks are rate limited together with other refreshes, so the JWKs endpoint is not called
        int requestsBeforeHealthChecks = requests.get();
        for (int i = 0; i < 5; i++) {
            assertEquals(Status.DOWN, health());
        }
        assertEquals(requestsBeforeHealthChecks, requests.get());
    }

}
