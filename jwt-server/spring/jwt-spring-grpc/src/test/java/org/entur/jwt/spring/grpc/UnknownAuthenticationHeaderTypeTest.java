package org.entur.jwt.spring.grpc;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.entur.jwt.junit5.AuthorizationServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
/**
 * 
 * Test accessing methods with an unknown token token type. We only accept Bearer types.
 * 
 */

@AuthorizationServer
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@DirtiesContext
public class UnknownAuthenticationHeaderTypeTest extends AbstractGrpcTest {

    @LocalServerPort
    private int randomServerPort;
    
    @Test 
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