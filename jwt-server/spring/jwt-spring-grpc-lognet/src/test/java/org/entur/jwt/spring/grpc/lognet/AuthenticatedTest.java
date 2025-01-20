package org.entur.jwt.spring.grpc.lognet;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.junit.jupiter.api.Test;
import org.lognet.springboot.grpc.security.GrpcSecurity;
import org.lognet.springboot.grpc.security.GrpcSecurityConfigurerAdapter;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
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

    @TestConfiguration
    public class GrpcSecurityConfiguration extends GrpcSecurityConfigurerAdapter {
        @Override
        public void configure(GrpcSecurity builder) throws Exception {
            System.out.println("Ding dong");
        }
    }

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