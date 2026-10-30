package org.entur.jwt.spring.grpc;

import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.ApplicationContext;
import org.springframework.grpc.server.security.AuthenticationProcessInterceptor;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import static com.google.common.truth.Truth.assertThat;

/**
 * Test accessing methods with both JWT and authorization disabled: anonymous access is allowed.
 *
 */

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {"entur.jwt.enabled=false", "entur.authorization.enabled=false"})
@DirtiesContext
public class DisabledJwtAndAuthorizationTest extends AbstractGrpcTest {

    @Autowired
    private ApplicationContext context;

    @Test
    public void testNoAuthenticationInterceptor() {
        assertThat(context.getBeanNamesForType(AuthenticationProcessInterceptor.class)).isEmpty();
    }

    @Test
    public void testProtectedResourceWithoutToken() {
        GreetingResponse response = stub().protectedWithPartnerTenant(greetingRequest);

        assertThat(response.getMessage()).isEqualTo("Hello protected tenant");
    }

}
