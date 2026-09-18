package org.entur.jwt.spring.grpc.perf;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.decode.cache.DecodedJwtCacheJwtDecoder;
import org.entur.jwt.spring.grpc.AbstractGrpcTest;
import org.entur.jwt.spring.grpc.JwtCallCredentials;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.entur.jwt.spring.grpc.test.GreetingServiceGrpc;
import org.entur.jwt.spring.grpc.test.GreetingServiceGrpc.GreetingServiceBlockingStub;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Back-to-back gRPC call benchmark against a real, fully started Spring Boot context
 * (embedded gRPC server on a real TCP loopback port, real security interceptor chain,
 * real JWKS mock issuer), with the decoded-JWT cache <b>enabled</b> (this branch's
 * optimization). Repeated tokens hit the decoded-JWT cache instead of being fully
 * re-verified, still going through the whole gRPC stack end to end over the network
 * interface (not an in-process channel).
 * <p>
 * See {@link DecodedJwtCacheGrpcBenchmarkNoCacheTest} for the equivalent benchmark with
 * the cache disabled, for direct comparison.
 * <p>
 * Test methods run in a fixed, explicit order ({@link Order}) and each scenario has a
 * large, independent warm-up phase, so that results are not skewed by JIT/GC/channel
 * warm-up carried over from a previously run method sharing the same Spring context/JVM.
 * <p>
 * Disabled by default - not part of the regular build. Remove {@code @Disabled} to run
 * manually.
 */
@Tag("performance")
@Disabled("Manual benchmark - not meant to run as part of the regular build")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@AuthorizationServer("a")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "entur.jwt.tenants.a.decoder-cache.enabled=true",
        "entur.jwt.jwk.cache.preemptive.eager.enabled=true",
        // suppress per-request log noise so it doesn't distort request timings/output
        "logging.level.org.entur=WARN",
        "logging.level.org.springframework=WARN",
        "logging.level.io.grpc=WARN",
})
@DirtiesContext
public class DecodedJwtCacheGrpcBenchmarkCachedTest extends AbstractGrpcTest {

    // large enough that each scenario independently reaches JIT/GC/channel steady state,
    // regardless of execution order or warm-up carried over from other methods
    private static final int WARMUP_REQUESTS = 20_000;
    private static final int REQUESTS = 10_000;

    // 15 parallel clients, 2 tokens each (30 tokens total) - matches abt-core's observed
    // peak (08:00/16:00) concurrent client count, per Entur Compass, with each client
    // presenting 2 distinct tokens
    private static final int CLIENTS = 15;
    private static final int TOKENS_PER_CLIENT = 2;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private JwkSourceMap jwkSourceMap;

    @BeforeEach
    public void readinessProbe() throws Exception {
        // make sure JWKs are loaded before timing anything
        Map<String, JWKSource> jwkSources = jwkSourceMap.getJwkSources();
        for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {
            JWKSelector selector = mock(JWKSelector.class);
            when(selector.select(any())).thenReturn(List.of(mock(JWK.class)));
            entry.getValue().get(selector, null);
        }

        assertThat(jwtDecoder).isInstanceOf(DecodedJwtCacheJwtDecoder.class);
        ((DecodedJwtCacheJwtDecoder) jwtDecoder).clear();
    }

    @Test
    @Order(1)
    public void singleTokenReused(@AccessToken(by = "a", audience = "https://my.audience") String token) {
        ManagedChannel channel = ManagedChannelBuilder.forAddress("localhost", 9090).usePlaintext().build();
        try {
            GreetingServiceBlockingStub stub = GreetingServiceGrpc.newBlockingStub(channel)
                    .withCallCredentials(new JwtCallCredentials(token));
            GrpcBenchmarkSupport.GrpcCall[] calls = {
                    i -> assertProtectedCallSucceeds(stub)
            };

            GrpcBenchmarkSupport.Stats stats = GrpcBenchmarkSupport.measureParallel(
                    "decoded-JWT cache enabled, single token reused (100% cache-hit rate)",
                    REQUESTS, WARMUP_REQUESTS, calls);

            assertTrue(stats.opsPerSecond() > 0);
        } finally {
            channel.shutdown();
        }
    }

    @Test
    @Order(2)
    public void tokenPoolReused(
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
            @AccessToken(by = "a", audience = "https://my.audience", scope = "20") String token20,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "21") String token21,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "22") String token22,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "23") String token23,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "24") String token24,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "25") String token25,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "26") String token26,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "27") String token27,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "28") String token28,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "29") String token29,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "30") String token30) {

        String[] tokens = {token1, token2, token3, token4, token5, token6, token7, token8, token9, token10, token11, token12, token13, token14, token15, token16, token17, token18, token19, token20, token21, token22, token23, token24, token25, token26, token27, token28, token29, token30};

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
            GrpcBenchmarkSupport.Stats stats = GrpcBenchmarkSupport.measureParallel(
                    "decoded-JWT cache enabled, " + CLIENTS + " parallel clients, " + TOKENS_PER_CLIENT
                            + " tokens each (" + tokens.length + " tokens total)",
                    REQUESTS, WARMUP_REQUESTS, calls);

            assertTrue(stats.opsPerSecond() > 0);
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
