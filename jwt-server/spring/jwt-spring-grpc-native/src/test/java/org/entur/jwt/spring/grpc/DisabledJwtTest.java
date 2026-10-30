package org.entur.jwt.spring.grpc;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.health.v1.HealthCheckRequest;
import io.grpc.health.v1.HealthCheckResponse;
import io.grpc.health.v1.HealthGrpc;
import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test accessing methods with JWT disabled, but authorization enabled: like for the web modules,
 * only the permit-all methods are accessible (tokens are not processed).
 *
 */

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {"entur.jwt.enabled=false"})
@DirtiesContext
public class DisabledJwtTest extends AbstractGrpcTest {

    @Test
    public void testProtectedResourceWithoutToken() {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub().protectedWithPartnerTenant(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }

    @Test
    public void testProtectedResourceWithToken(@AccessToken(audience = "https://my.audience") String header) {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub(header).protectedWithPartnerTenant(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }

    @Test
    public void testUnprotectedResource() {
        GreetingResponse response = stub().unprotected(greetingRequest);

        assertThat(response.getMessage()).isEqualTo("Hello unprotected");
    }

    @Test
    public void testUnprotectedResourceWithToken(@AccessToken(audience = "https://my.audience") String header) {
        GreetingResponse response = stub(header).unprotectedWithOptionalTenant(greetingRequest);

        assertThat(response.getMessage()).isEqualTo("Hello unprotected method with tenant not present");
    }

    @Test
    public void testGrpcHealth() throws Exception {
        HealthCheckRequest healthCheckRequest = HealthCheckRequest.newBuilder().build();
        HealthCheckResponse.ServingStatus servingStatus = HealthGrpc.newFutureStub(managedChannel).check(healthCheckRequest).get().getStatus();

        assertThat(servingStatus).isEqualTo(HealthCheckResponse.ServingStatus.SERVING);
    }

}
