package org.entur.jwt.spring.grpc;

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
import org.springframework.test.annotation.DirtiesContext;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static com.google.common.truth.Truth.assertThat;

/**
 *
 * Test that the JWT claim mappings are passed to a {@linkplain GrpcMdcAdapter}, i.e. that the MDC interceptor runs after authentication.
 *
 */

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@DirtiesContext
public class GrpcMdcTest extends AbstractGrpcTest {

    @TestConfiguration
    static class MdcConfiguration {

        @Bean
        public RecordingGrpcMdcAdapter grpcMdcAdapter() {
            return new RecordingGrpcMdcAdapter();
        }
    }

    static class RecordingGrpcMdcAdapter implements GrpcMdcAdapter {

        private final Map<String, String> values = new ConcurrentHashMap<>();

        @Override
        public void put(String key, String value) {
            values.put(key, value);
        }

        @Override
        public void remove(String key) {
            values.remove(key);
        }

        @Override
        public String get(String key) {
            return values.get(key);
        }

        @Override
        public void clear() {
            values.clear();
        }
    }

    @Autowired
    private RecordingGrpcMdcAdapter adapter;

    @Test
    public void testMappedClaimsArePassedToAdapter(@AccessToken(audience = "https://my.audience") @StringClaim(name = "azp", value = "my-client") String header) {
        GreetingResponse response = stub(header).protectedWithPartnerTenant(greetingRequest);

        assertThat(response.getMessage()).isEqualTo("Hello protected tenant");

        assertThat(adapter.get("azp")).isEqualTo("my-client");
        assertThat(adapter.get("issuer")).isNotNull();
    }

}
