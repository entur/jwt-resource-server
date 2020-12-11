package org.entur.jwt.spring.grpc;

import static com.google.common.truth.Truth.assertThat;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.headers.KeyIdHeader;
import org.entur.jwt.junit5.sabotage.Signature;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.annotation.DirtiesContext;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
/**
 * 
 * Test accessing methods without an unknown token token.
 * 
 * Invalid tokens should always result in error.
 * 
 */

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@DirtiesContext
public class InvalidAuthenticationTokenTest extends AbstractGrpcTest {
    
    @Test 
    public void testUnprotectedResource() {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub("Bearer hvaomshelst").unprotected(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }
    
    @Test 
    public void testProtectedResource() {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub("Bearer hvaomshelst").protectedWithPartnerTenant(greetingRequest);
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
    public void testProtectedResourceWithInvalidKeyId(@AccessToken @KeyIdHeader("abc") String header) {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub(header).protectedWithPartnerTenant(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }
    
}