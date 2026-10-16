package org.entur.jwt.spring.perf;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.actuate.AbstractActuatorTest;
import org.entur.jwt.spring.decode.ClosableJwtDecoders;
import org.entur.jwt.spring.decode.cache.DecodedJwtCacheJwtDecoder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Back-to-back HTTP request benchmark against a real, fully started Spring Boot context
 * (embedded server on a random port, real security filter chain, real JWKS mock issuer),
 * with the decoded-JWT cache <b>enabled</b> (this branch's optimization). Repeated tokens
 * hit the decoded-JWT cache instead of being fully re-verified, still going through the
 * whole HTTP stack end to end.
 * <p>
 * See {@link DecodedJwtCacheHttpBenchmarkNoCacheTest} for the equivalent benchmark with
 * the cache disabled, for direct comparison.
 * <p>
 * Test methods run in a fixed, explicit order ({@link Order}) and each scenario has a
 * large, independent warm-up phase, so that results are not skewed by JIT/GC/connection-pool
 * warm-up carried over from a previously run method sharing the same Spring context/JVM.
 * <p>
 * Disabled by default - not part of the regular build. Remove {@code @Disabled} to run
 * manually.
 */
@Tag("performance")
@Disabled("Manual benchmark - not meant to run as part of the regular build")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@AuthorizationServer("a")
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@TestPropertySource(properties = {
        "entur.jwt.tenants.a.decoder-cache.enabled=true",
        "entur.jwt.jwk.cache.preemptive.eager.enabled=true",
        // suppress per-request log noise so it doesn't distort request timings/output
        "logging.level.org.entur=WARN",
        "logging.level.org.springframework=WARN",
})
public class DecodedJwtCacheHttpBenchmarkCachedTest extends AbstractActuatorTest {

    // large enough that each scenario independently reaches JIT/GC/connection-pool steady
    // state, regardless of execution order or warm-up carried over from other methods
    private static final int WARMUP_REQUESTS = 20_000;
    private static final int REQUESTS = 10_000;

    // 10 parallel clients, 2 tokens each (20 tokens total) - reduced from abt-core's
    // observed peak (08:00/16:00) concurrent client count, per Entur Compass, to
    // investigate throughput scaling with fewer concurrent clients
    private static final int CLIENTS = 10;
    private static final int TOKENS_PER_CLIENT = 2;

    @LocalServerPort
    private int randomServerPort;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private ClosableJwtDecoders closableJwtDecoders;

    @BeforeEach
    public void readinessProbe() throws Exception {
        HttpBenchmarkSupport.assertJacocoAgentDisabled();

        // make sure JWKs are loaded before timing anything
        HttpHeaders headers = new HttpHeaders();
        HttpEntity<String> entity = new HttpEntity<>(headers);

        String url = "http://localhost:" + randomServerPort + "/actuator/health/readiness";
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
            waitForHealth();

            response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
            assertTrue(response.getStatusCode().is2xxSuccessful());
        }

        JwtDecoder decoder = closableJwtDecoders.getJwtDecoders().get("https://mock.issuer.a.xyz");
        assertThat(decoder).isInstanceOf(DecodedJwtCacheJwtDecoder.class);
        ((DecodedJwtCacheJwtDecoder) decoder).clear();
    }

    @Test
    @Order(1)
    public void singleTokenReused(@AccessToken(by = "a", audience = "mock.my.audience") String token) {
        RawHttpClientSupport client = new RawHttpClientSupport();
        HttpBenchmarkSupport.HttpCall[] calls = {
                i -> client.assertProtectedRequestSucceeds(randomServerPort, token, "Hello protected")
        };

        HttpBenchmarkSupport.Stats stats = HttpBenchmarkSupport.measureParallel(
                "decoded-JWT cache enabled, single token reused (100% cache-hit rate)",
                REQUESTS, WARMUP_REQUESTS, calls);

        assertTrue(stats.opsPerSecond() > 0);
    }

    @Test
    @Order(2)
    public void tokenPoolReused(
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "1") String token1,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "2") String token2,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "3") String token3,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "4") String token4,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "5") String token5,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "6") String token6,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "7") String token7,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "8") String token8,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "9") String token9,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "10") String token10,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "11") String token11,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "12") String token12,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "13") String token13,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "14") String token14,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "15") String token15,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "16") String token16,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "17") String token17,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "18") String token18,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "19") String token19,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "20") String token20) {

        String[] tokens = {token1, token2, token3, token4, token5, token6, token7, token8, token9, token10, token11, token12, token13, token14, token15, token16, token17, token18, token19, token20};

        HttpBenchmarkSupport.HttpCall[] calls = new HttpBenchmarkSupport.HttpCall[CLIENTS];
        for (int c = 0; c < CLIENTS; c++) {
            RawHttpClientSupport client = new RawHttpClientSupport();
            String[] clientTokens = new String[TOKENS_PER_CLIENT];
            for (int t = 0; t < TOKENS_PER_CLIENT; t++) {
                clientTokens[t] = tokens[c * TOKENS_PER_CLIENT + t];
            }
            calls[c] = i -> client.assertProtectedRequestSucceeds(randomServerPort, clientTokens[i % clientTokens.length], "Hello protected");
        }

        HttpBenchmarkSupport.Stats stats = HttpBenchmarkSupport.measureParallel(
                "decoded-JWT cache enabled, " + CLIENTS + " parallel clients, " + TOKENS_PER_CLIENT + " tokens each ("
                        + tokens.length + " tokens total)",
                REQUESTS, WARMUP_REQUESTS, calls);

        assertTrue(stats.opsPerSecond() > 0);
    }
}
