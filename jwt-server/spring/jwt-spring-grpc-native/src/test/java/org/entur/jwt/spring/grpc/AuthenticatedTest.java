package org.entur.jwt.spring.grpc;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.claim.JsonClaim;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.test.annotation.DirtiesContext;

import java.util.List;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;


/**
 *
 * Test accessing methods with a valid bearer token.
 *
 */

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@DirtiesContext
public class AuthenticatedTest extends AbstractGrpcTest {

    @Autowired
    private GreetingController greetingController;

    @Test
    public void testUnprotectedResource(@AccessToken(audience = "https://my.audience") String header) {
        GreetingResponse response = stub(header).unprotected(greetingRequest);

        assertThat(response.getMessage()).isEqualTo("Hello unprotected");
    }

    @Test
    public void testProtectedResource(@AccessToken(audience = "https://my.audience") String header) {
        GreetingResponse response = stub(header).protectedWithPartnerTenant(greetingRequest);

        assertThat(response.getMessage()).isEqualTo("Hello protected tenant");
    }

    @Test
    public void testKeycloakClientRolesAreNotMappedWithoutClientId(@AccessToken(audience = "https://my.audience") @JsonClaim(name = "resource_access", value = "{\"booking-api\":{\"roles\":[\"booking-reader\"]},\"reporting-ui\":{\"roles\":[\"admin\"]}}") String header) {
        GreetingResponse response = stub(header).protectedWithPartnerTenant(greetingRequest);

        assertThat(response.getMessage()).isEqualTo("Hello protected tenant");

        List<String> roles = greetingController.getLastProtectedToken().getAuthorities().stream().map(GrantedAuthority::getAuthority).filter(a -> a.startsWith("ROLE_")).toList();
        assertThat(roles).isEmpty();
    }

    @Test
    public void testProtectedResourceWithoutHeader() {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub().protectedWithPartnerTenant(greetingRequest);
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