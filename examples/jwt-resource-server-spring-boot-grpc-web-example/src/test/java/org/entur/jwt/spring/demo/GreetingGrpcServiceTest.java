package org.entur.jwt.spring.demo;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.demo.grpc.GreetingRequest;
import org.entur.jwt.spring.demo.grpc.GreetingResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * gRPC methods, with and without a valid bearer token.
 */
@AuthorizationServer
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext
public class GreetingGrpcServiceTest {

    private final GrpcClient client = new GrpcClient();

    @AfterEach
    public void close() throws InterruptedException {
        client.close();
    }

    @Test
    public void testUnprotectedMethod() {
        GreetingResponse response = client.stub().unprotected(GreetingRequest.getDefaultInstance());

        assertThat(response.getMessage()).isEqualTo("Hello unprotected");
    }

    @Test
    public void testProtectedMethod(@AccessToken(audience = "https://my.audience") String token) {
        GreetingResponse response = client.stub(token).protectedGreeting(GreetingRequest.getDefaultInstance());

        assertThat(response.getMessage()).isEqualTo("Hello protected");
    }

    @Test
    public void testProtectedMethodWithoutToken() {
        StatusRuntimeException exception = assertThrows(StatusRuntimeException.class, () -> client.stub().protectedGreeting(GreetingRequest.getDefaultInstance()));

        assertThat(exception.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
    }
}
