package org.entur.jwt.spring.grpc;

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
import org.springframework.test.context.TestPropertySource;

import java.util.List;

import static com.google.common.truth.Truth.assertThat;

/**
 *
 * Test that only the Keycloak client roles of the configured client are mapped to authorities.
 *
 */

@AuthorizationServer
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "entur.jwt.flavours.keycloak.client-id=booking-api",
})
@DirtiesContext
public class KeycloakClientRolesTest extends AbstractGrpcTest {

    @Autowired
    private GreetingController greetingController;

    @Test
    public void testOnlyRolesOfConfiguredClientAreMapped(@AccessToken(audience = "https://my.audience") @JsonClaim(name = "resource_access", value = "{\"booking-api\":{\"roles\":[\"booking-reader\"]},\"reporting-ui\":{\"roles\":[\"admin\"]},\"account\":{\"roles\":[\"manage-account\"]}}") String header) {
        GreetingResponse response = stub(header).protectedWithPartnerTenant(greetingRequest);

        assertThat(response.getMessage()).isEqualTo("Hello protected tenant");

        List<String> roles = greetingController.getLastProtectedToken().getAuthorities().stream().map(GrantedAuthority::getAuthority).filter(a -> a.startsWith("ROLE_")).toList();
        assertThat(roles).containsExactly("ROLE_booking-reader");
    }

}
