package org.entur.jwt.spring.grpc;

import static com.google.common.truth.Truth.assertThat;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.headers.KeyIdHeader;
import org.entur.jwt.junit5.sabotage.Signature;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
/**
 * 
 * Test readiness probe repair. 
 * 
 * Rename the jwk file so that it first cannot be found, check that state is down.
 * Then later restore the file and verify that state is up. 
 * 
 */

@AuthorizationServer("unreliable")
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class AuthorizationServerDownTest extends AbstractGrpcTest {

    @LocalServerPort
    private int randomServerPort;
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Value("${entur.jwt.tenants.unreliable.jwk.location}")
    private String jwkLocation;

    @BeforeEach 
    public void before() {
        File jwkFile = new File(jwkLocation.substring(7));
        File jwkRenameFile = new File(jwkFile.getParentFile(), jwkFile.getName() + ".renamed");
        
        assertTrue(jwkFile.renameTo(jwkRenameFile));
    }

    @AfterEach 
    public void after() {
        File jwkFile = new File(jwkLocation.substring(7));
        File jwkRenameFile = new File(jwkFile.getParentFile(), jwkFile.getName() + ".renamed");
        
        assertTrue(jwkRenameFile.renameTo(jwkFile));
    }
    
    @Test 
    public void testProtectedResource() {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub().protectedWithPartnerTenant(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }
    
    @Test 
    public void testProtectedResource(@AccessToken String header) {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub(header).protectedWithPartnerTenant(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    }    

    @Test 
    public void testProtectedResourceWithInvalidSignature(@AccessToken @Signature String header) {
        System.out.println(header);
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub(header).protectedWithPartnerTenant(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    }
    
    @Test 
    public void testProtectedResourceWithInvalidKeyId(@AccessToken @KeyIdHeader("abc") String header) {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> {
            stub(header).protectedWithPartnerTenant(greetingRequest);
        });
        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    }
}