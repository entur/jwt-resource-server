package org.entur.jwt.spring.grpc.perf;

import com.nimbusds.jose.jwk.JWK;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.grpc.AbstractGrpcTest;
import org.entur.jwt.spring.grpc.JwtCallCredentials;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.entur.jwt.spring.grpc.test.GreetingServiceGrpc;
import org.entur.jwt.spring.grpc.test.GreetingServiceGrpc.GreetingServiceBlockingStub;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Cold-start gRPC call benchmark, with the decoded-JWT cache <b>disabled</b>,
 * approximating {@code master} behaviour (which has no decoded-JWT cache at all). There
 * is no warm-up phase at all: the very first call is the very first thing timed. A
 * single continuous run of back-to-back calls is made, round-robin across a pool of 20
 * tokens (a realistic number of distinct client tokens seen concurrently in production),
 * and throughput is reported at cumulative wall-clock checkpoints of 1, 2, 3, 4, 5, 10
 * and 15 seconds - both the throughput of that individual segment and the cumulative
 * throughput since the first call.
 * <p>
 * See {@link DecodedJwtCacheGrpcBenchmarkColdStartCachedTest} for the equivalent
 * benchmark with the cache enabled, for direct comparison.
 * <p>
 * Disabled by default - not part of the regular build. Remove {@code @Disabled} to run
 * manually.
 */
@Tag("performance")
@Disabled("Manual benchmark - not meant to run as part of the regular build")
@AuthorizationServer("a")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        // suppress per-request log noise so it doesn't distort request timings/output
        "logging.level.org.entur=WARN",
        "logging.level.org.springframework=WARN",
        "logging.level.io.grpc=WARN",
})
@DirtiesContext
public class DecodedJwtCacheGrpcBenchmarkColdStartNoCacheTest extends AbstractGrpcTest {

    private static final int[] CHECKPOINT_SECONDS = {1, 2, 3, 4, 5, 10, 15, 30, 60};

    // 10 parallel clients, 2 tokens each (20 tokens total) - reduced from abt-core's
    // observed peak (08:00/16:00) concurrent client count, per Entur Compass, to
    // investigate throughput scaling with fewer concurrent clients
    private static final int CLIENTS = 10;
    private static final int TOKENS_PER_CLIENT = 2;

    @Autowired
    private JwkSourceMap jwkSourceMap;

    @BeforeEach
    public void readinessProbe() throws Exception {
        GrpcBenchmarkSupport.assertJacocoAgentDisabled();

        // make sure JWKs are loaded before timing anything - this is not itself part of
        // the "cold start", it merely establishes the same server-side readiness as the
        // other benchmarks in this package
        Map<String, JWKSource> jwkSources = jwkSourceMap.getJwkSources();
        for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {
            JWKSelector selector = mock(JWKSelector.class);
            when(selector.select(any())).thenReturn(List.of(mock(JWK.class)));
            entry.getValue().get(selector, null);
        }
    }

    @Test
    public void coldStart(
            @AccessToken(by = "a", audience = "https://my.audience", scope = "1") String token1,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "2") String token2,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "3") String token3,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "4") String token4,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "5") String token5,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "6") String token6,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "7") String token7,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "8") String token8,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "9") String token9,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "10") String token10,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "11") String token11,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "12") String token12,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "13") String token13,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "14") String token14,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "15") String token15,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "16") String token16,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "17") String token17,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "18") String token18,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "19") String token19,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "20") String token20) {

        String[] tokens = {token1, token2, token3, token4, token5, token6, token7, token8, token9, token10, token11, token12, token13, token14, token15, token16, token17, token18, token19, token20};

        ManagedChannel[] channels = new ManagedChannel[CLIENTS];
        GrpcBenchmarkSupport.GrpcCall[] calls = new GrpcBenchmarkSupport.GrpcCall[CLIENTS];
        for (int c = 0; c < CLIENTS; c++) {
            ManagedChannel channel = ManagedChannelBuilder.forAddress("localhost", 9090).usePlaintext().build();
            channels[c] = channel;
            String[] clientTokens = new String[TOKENS_PER_CLIENT];
            for (int t = 0; t < TOKENS_PER_CLIENT; t++) {
                clientTokens[t] = tokens[c * TOKENS_PER_CLIENT + t];
            }
            GreetingServiceBlockingStub[] clientStubs = new GreetingServiceBlockingStub[clientTokens.length];
            for (int t = 0; t < clientTokens.length; t++) {
                clientStubs[t] = GreetingServiceGrpc.newBlockingStub(channel)
                        .withCallCredentials(new JwtCallCredentials(clientTokens[t]));
            }
            calls[c] = i -> assertProtectedCallSucceeds(clientStubs[i % clientStubs.length]);
        }

        try {
            GrpcBenchmarkSupport.measureColdStartIntervalsParallel(
                    "no decoded-JWT cache, cold start, " + CLIENTS + " parallel clients, " + TOKENS_PER_CLIENT
                            + " tokens each (" + tokens.length + " tokens total)",
                    CHECKPOINT_SECONDS, calls);
        } finally {
            for (ManagedChannel channel : channels) {
                channel.shutdown();
            }
        }
    }

    private void assertProtectedCallSucceeds(GreetingServiceBlockingStub stub) {
        GreetingResponse response = stub.protectedWithPartnerTenant(greetingRequest);

        assertThat(response.getMessage()).isEqualTo("Hello protected tenant");
    }
}
