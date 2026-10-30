package org.entur.jwt.spring.grpc;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.sabotage.Signature;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
/**
 * Test accessing methods with authorization disabled: anonymous access is allowed,
 * but tokens which are present must still be valid.
 *
 */

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {"entur.authorization.enabled=false"})
@DirtiesContext
public class DisabledAuthorizationTest extends AbstractGrpcTest {

    @Test
    public void testProtectedResourceWithoutToken() {
        GreetingResponse response = stub().protectedWithPartnerTenant(greetingRequest);

        assertThat(response.getMessage()).isEqualTo("Hello protected tenant");
    }

    @Test
    public void testProtectedResource(@AccessToken(audience = "https://my.audience") String header) {
        GreetingResponse response = stub(header).protectedWithPartnerTenant(greetingRequest);

        assertThat(response.getMessage()).isEqualTo("Hello protected tenant");
    }

    @Test
    public void testResourceWithoutTokenIsAnonymous() {
        GreetingResponse response = stub().unprotectedWithOptionalTenant(greetingRequest);

        assertThat(response.getMessage()).isEqualTo("Hello unprotected method with tenant not present");
    }

    @Test
    public void testResourceWithTokenIsAuthenticated(@AccessToken(audience = "https://my.audience") String header) {
        GreetingResponse response = stub(header).unprotectedWithOptionalTenant(greetingRequest);

        // the token reaches the service, so that it can be checked manually (i.e. using GrpcAuthorization)
        assertThat(response.getMessage()).startsWith("Hello unprotected method with tenant present");
    }

    @Test
    public void testProtectedResourceWithInvalidToken() {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub("Bearer invalid").protectedWithPartnerTenant(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }

    @Test
    public void testProtectedResourceWithInvalidSignature(@AccessToken(audience = "https://my.audience") @Signature("cheat") String header) {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub(header).protectedWithPartnerTenant(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }

    @Test
    public void testProtectedResourceWrongAudience(@AccessToken(audience = "https://wrong.audience") String header) {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub(header).protectedWithPartnerTenant(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }

}
