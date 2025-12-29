package org.entur.jwt.spring.grpc;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.annotation.DirtiesContext;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
/**
 * 
 * Test accessing methods with an unknown token token type. We only accept Bearer types.
 * 
 */

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@DirtiesContext
public class UnknownAuthenticationHeaderTypeTest extends AbstractGrpcTest {

    @LocalServerPort
    private int randomServerPort;
    
    @Test
    @Disabled // invalid authentication does not result in unauthenticated
    public void testUnprotectedResource() {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub("Delegate Hvaomshelst").unprotected(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }
    
    @Test 
    public void testProtectedResource() {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub("Delegate hvaomshelst").protectedWithPartnerTenant(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }
    
    @Test
    @Disabled // invalid authentication does not result in unauthenticated
    public void testUnprotectedResourceNoTokenType() {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub("Hvaomshelst").unprotected(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }
    
    @Test 
    public void testProtectedResourceNoTokenType() {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub("hvaomshelst").protectedWithPartnerTenant(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }    
}