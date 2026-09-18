package org.entur.jwt.spring.grpc.perf;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.decode.cache.DecodedJwtCacheJwtDecoder;
import org.entur.jwt.spring.grpc.AbstractGrpcTest;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
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
        GrpcBenchmarkSupport.Stats stats = GrpcBenchmarkSupport.measure(
                "decoded-JWT cache enabled, single token reused (100% cache-hit rate)",
                REQUESTS, WARMUP_REQUESTS, i -> assertProtectedCallSucceeds(token));

        assertTrue(stats.opsPerSecond() > 0);
    }

    @Test
    @Order(2)
    public void tokenPoolReused(
            @AccessToken(by = "a", audience = "https://my.audience", scope = "1") String token1,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "2") String token2,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "3") String token3,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "4") String token4,
            @AccessToken(by = "a", audience = "https://my.audience", scope = "5") String token5) {

        String[] tokens = {token1, token2, token3, token4, token5};

        GrpcBenchmarkSupport.Stats stats = GrpcBenchmarkSupport.measure(
                "decoded-JWT cache enabled, pool of " + tokens.length + " tokens reused round-robin",
                REQUESTS, WARMUP_REQUESTS, i -> assertProtectedCallSucceeds(tokens[i % tokens.length]));

        assertTrue(stats.opsPerSecond() > 0);
    }

    private void assertProtectedCallSucceeds(String token) {
        GreetingResponse response = stub(token).protectedWithPartnerTenant(greetingRequest);

        assertThat(response.getMessage()).isEqualTo("Hello protected tenant");
    }
}
