package org.entur.jwt.spring.grpc;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.annotation.DirtiesContext;

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
    public void testProtectedResourceWithoutHeader() {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub().protectedWithPartnerTenant(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }


}