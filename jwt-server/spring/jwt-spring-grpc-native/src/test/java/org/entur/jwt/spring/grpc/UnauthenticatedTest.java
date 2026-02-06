package org.entur.jwt.spring.grpc;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.annotation.DirtiesContext;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
/**
 * Test accessing methods without a token.
 * 
 */

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@DirtiesContext
public class UnauthenticatedTest extends AbstractGrpcTest {

    @Test 
    public void testProtectedResource() {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub().protectedWithPartnerTenant(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }
    
    @Test 
    public void testUnprotectedResource() {
        GreetingResponse response = stub().unprotected(greetingRequest);
        
        assertThat(response.getMessage()).startsWith("Hello unprotected");
    }

}