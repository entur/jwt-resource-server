package org.entur.jwt.spring.perf;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.actuate.AbstractActuatorTest;
import org.entur.jwt.spring.decode.ClosableJwtDecoders;
import org.entur.jwt.spring.decode.cache.DecodedJwtCacheJwtDecoder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
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
 * Cold-start HTTP request benchmark, with the decoded-JWT cache <b>enabled</b>. Unlike
 * {@link DecodedJwtCacheHttpBenchmarkCachedTest}, there is no warm-up phase at all: the
 * very first request is the very first thing timed. A single continuous run of
 * back-to-back requests is made, round-robin across a pool of 30 tokens (a realistic
 * number of distinct client tokens seen concurrently in production), and throughput is reported at
 * cumulative wall-clock checkpoints of 1, 2, 3, 4, 5, 10 and 15 seconds - both the
 * throughput of that individual segment and the cumulative throughput since the first
 * request - so the cache warm-up curve (cold JIT/connection-pool/first-decode vs. steady
 * state) is visible within a single run.
 * <p>
 * See {@link DecodedJwtCacheHttpBenchmarkColdStartNoCacheTest} for the equivalent
 * benchmark with the cache disabled, for direct comparison.
 * <p>
 * Disabled by default - not part of the regular build. Remove {@code @Disabled} to run
 * manually.
 */
@Tag("performance")
@Disabled("Manual benchmark - not meant to run as part of the regular build")
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
public class DecodedJwtCacheHttpBenchmarkColdStartCachedTest extends AbstractActuatorTest {

    private static final int[] CHECKPOINT_SECONDS = {1, 2, 3, 4, 5, 10, 15};

    // 15 parallel clients, 2 tokens each (30 tokens total) - matches abt-core's observed
    // peak (08:00/16:00) concurrent client count, per Entur Compass, with each client
    // presenting 2 distinct tokens
    private static final int CLIENTS = 15;
    private static final int TOKENS_PER_CLIENT = 2;

    @LocalServerPort
    private int randomServerPort;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private ClosableJwtDecoders closableJwtDecoders;

    @BeforeEach
    public void readinessProbe() throws Exception {
        // make sure JWKs are loaded before timing anything - this is not itself part of
        // the "cold start", it merely establishes the same server-side readiness as the
        // other benchmarks in this package
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
    public void coldStart(
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
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "20") String token20,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "21") String token21,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "22") String token22,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "23") String token23,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "24") String token24,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "25") String token25,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "26") String token26,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "27") String token27,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "28") String token28,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "29") String token29,
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "30") String token30) {

        String[] tokens = {token1, token2, token3, token4, token5, token6, token7, token8, token9, token10, token11, token12, token13, token14, token15, token16, token17, token18, token19, token20, token21, token22, token23, token24, token25, token26, token27, token28, token29, token30};

        HttpBenchmarkSupport.HttpCall[] calls = new HttpBenchmarkSupport.HttpCall[CLIENTS];
        for (int c = 0; c < CLIENTS; c++) {
            RawHttpClientSupport client = new RawHttpClientSupport();
            String[] clientTokens = new String[TOKENS_PER_CLIENT];
            for (int t = 0; t < TOKENS_PER_CLIENT; t++) {
                clientTokens[t] = tokens[c * TOKENS_PER_CLIENT + t];
            }
            calls[c] = i -> client.assertProtectedRequestSucceeds(randomServerPort, clientTokens[i % clientTokens.length], "Hello protected");
        }

        HttpBenchmarkSupport.measureColdStartIntervalsParallel(
                "decoded-JWT cache enabled, cold start, " + CLIENTS + " parallel clients, " + TOKENS_PER_CLIENT
                        + " tokens each (" + tokens.length + " tokens total)",
                CHECKPOINT_SECONDS, calls);
    }
}
