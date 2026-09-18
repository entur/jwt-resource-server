package org.entur.jwt.spring.perf;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.actuate.AbstractActuatorTest;
import org.entur.jwt.spring.rest.Greeting;
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
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cold-start HTTP request benchmark, with the decoded-JWT cache <b>disabled</b>,
 * approximating {@code master} behaviour (which has no decoded-JWT cache at all). There
 * is no warm-up phase at all: the very first request is the very first thing timed. A
 * single continuous run of back-to-back requests is made, round-robin across a pool of 20
 * tokens (a realistic number of distinct client tokens seen concurrently in production),
 * and throughput is reported at cumulative wall-clock checkpoints of 1, 2, 3, 4, 5, 10
 * and 15 seconds - both the throughput of that individual segment and the cumulative
 * throughput since the first request.
 * <p>
 * See {@link DecodedJwtCacheHttpBenchmarkColdStartCachedTest} for the equivalent
 * benchmark with the cache enabled, for direct comparison.
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
        // suppress per-request log noise so it doesn't distort request timings/output
        "logging.level.org.entur=WARN",
        "logging.level.org.springframework=WARN",
})
public class DecodedJwtCacheHttpBenchmarkColdStartNoCacheTest extends AbstractActuatorTest {

    private static final int[] CHECKPOINT_SECONDS = {1, 2, 3, 4, 5, 10, 15};

    @LocalServerPort
    private int randomServerPort;

    @Autowired
    private TestRestTemplate restTemplate;

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
            @AccessToken(by = "a", audience = "mock.my.audience", scope = "20") String token20) {

        String[] tokens = {token1, token2, token3, token4, token5, token6, token7, token8, token9, token10, token11, token12, token13, token14, token15, token16, token17, token18, token19, token20};

        HttpBenchmarkSupport.measureColdStartIntervals(
                "no decoded-JWT cache, cold start, pool of 20 tokens reused round-robin",
                CHECKPOINT_SECONDS, i -> assertProtectedRequestSucceeds(tokens[i % tokens.length]));
    }

    private void assertProtectedRequestSucceeds(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        String url = "http://localhost:" + randomServerPort + "/protected";
        ResponseEntity<Greeting> response = restTemplate.exchange(url, HttpMethod.GET, entity, Greeting.class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
    }
}
