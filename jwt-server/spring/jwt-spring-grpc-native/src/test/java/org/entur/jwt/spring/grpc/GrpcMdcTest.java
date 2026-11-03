package org.entur.jwt.spring.grpc;

import io.grpc.ForwardingServerCallListener.SimpleForwardingServerCallListener;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCall.Listener;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.claim.StringClaim;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.grpc.server.GlobalServerInterceptor;
import org.springframework.test.annotation.DirtiesContext;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static com.google.common.truth.Truth.assertThat;
import static org.awaitility.Awaitility.await;

/**
 *
 * Test that the JWT claim mappings are available to a {@linkplain GrpcMdcAdapter} while the call is processed, and removed again afterwards.
 *
 */

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@DirtiesContext
public class GrpcMdcTest extends AbstractGrpcTest {

    @TestConfiguration
    static class MdcConfiguration {

        @Bean
        public PerThreadGrpcMdcAdapter grpcMdcAdapter() {
            return new PerThreadGrpcMdcAdapter();
        }

        @Bean
        @GlobalServerInterceptor
        public MdcRecordingInterceptor mdcRecordingInterceptor(PerThreadGrpcMdcAdapter adapter) {
            return new MdcRecordingInterceptor(adapter);
        }
    }

    /** Behaves like a thread-local MDC, but can be inspected from any thread. */
    static class PerThreadGrpcMdcAdapter implements GrpcMdcAdapter {

        private final Map<Thread, Map<String, String>> values = new ConcurrentHashMap<>();

        @Override
        public void put(String key, String value) {
            values.computeIfAbsent(Thread.currentThread(), t -> new ConcurrentHashMap<>()).put(key, value);
        }

        @Override
        public void remove(String key) {
            Map<String, String> threadValues = values.get(Thread.currentThread());
            if (threadValues != null) {
                threadValues.remove(key);
            }
        }

        @Override
        public String get(String key) {
            Map<String, String> threadValues = values.get(Thread.currentThread());
            return threadValues != null ? threadValues.get(key) : null;
        }

        @Override
        public void clear() {
            values.remove(Thread.currentThread());
        }

        Map<String, String> remaining() {
            Map<String, String> remaining = new HashMap<>();
            values.values().forEach(remaining::putAll);
            return remaining;
        }
    }

    /** Runs after the MDC interceptor, and records what the service method would see. */
    static class MdcRecordingInterceptor implements ServerInterceptor, Ordered {

        private final PerThreadGrpcMdcAdapter adapter;

        private final AtomicReference<Map<String, String>> onInterceptCall = new AtomicReference<>();
        private final AtomicReference<Map<String, String>> onHalfClose = new AtomicReference<>();

        MdcRecordingInterceptor(PerThreadGrpcMdcAdapter adapter) {
            this.adapter = adapter;
        }

        @Override
        public <ReqT, RespT> Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
            onInterceptCall.set(current());

            Listener<ReqT> delegate = next.startCall(call, headers);
            return new SimpleForwardingServerCallListener<>(delegate) {
                @Override
                public void onHalfClose() {
                    onHalfClose.set(current());
                    super.onHalfClose();
                }
            };
        }

        private Map<String, String> current() {
            Map<String, String> current = new HashMap<>();
            for (String key : new String[] { "issuer", "azp" }) {
                String value = adapter.get(key);
                if (value != null) {
                    current.put(key, value);
                }
            }
            return current;
        }

        @Override
        public int getOrder() {
            return Ordered.LOWEST_PRECEDENCE;
        }
    }

    @Autowired
    private PerThreadGrpcMdcAdapter adapter;

    @Autowired
    private MdcRecordingInterceptor recorder;

    @Test
    public void testMappedClaimsAreAvailableToServiceMethod(@AccessToken(audience = "https://my.audience") @StringClaim(name = "azp", value = "my-client") String header) {
        GreetingResponse response = stub(header).protectedWithPartnerTenant(greetingRequest);

        assertThat(response.getMessage()).isEqualTo("Hello protected tenant");

        assertThat(recorder.onInterceptCall.get()).containsEntry("azp", "my-client");
        assertThat(recorder.onInterceptCall.get()).containsKey("issuer");
        assertThat(recorder.onHalfClose.get()).containsEntry("azp", "my-client");
        assertThat(recorder.onHalfClose.get()).containsKey("issuer");
    }

    @Test
    public void testMappedClaimsAreRemovedWhenCallCompletes(@AccessToken(audience = "https://my.audience") @StringClaim(name = "azp", value = "my-client") String header) {
        stub(header).protectedWithPartnerTenant(greetingRequest);
        stub(header).protectedWithPartnerTenant(greetingRequest);

        await().atMost(5, TimeUnit.SECONDS).untilAsserted(() -> assertThat(adapter.remaining()).isEmpty());
    }

}
