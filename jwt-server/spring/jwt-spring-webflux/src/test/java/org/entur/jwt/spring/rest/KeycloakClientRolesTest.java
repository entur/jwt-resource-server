package org.entur.jwt.spring.rest;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.claim.JsonClaim;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;

import static com.google.common.truth.Truth.assertThat;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * Test that only the Keycloak client roles of the configured client are mapped to authorities.
 */

@AuthorizationServer
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@TestPropertySource(properties = {
        "entur.jwt.flavours.keycloak.client-id=booking-api",
})
public class KeycloakClientRolesTest {

    @Autowired
    private WebTestClient webTestClient;

    @Test
    public void testOnlyRolesOfConfiguredClientAreMapped(@AccessToken(audience = "mock.my.audience") @JsonClaim(name = "resource_access", value = "{\"booking-api\":{\"roles\":[\"booking-reader\"]},\"reporting-ui\":{\"roles\":[\"admin\"]},\"account\":{\"roles\":[\"manage-account\"]}}") String token) {
        Greeting greeting = webTestClient
            .get()
            .uri("/protected")
            .header(AUTHORIZATION, token)
            .exchange()
            .expectStatus().is2xxSuccessful()
            .returnResult(Greeting.class)
            .getResponseBody().blockLast();

        assertThat(greeting.getAuthorities()).containsExactly("FACTOR_BEARER", "ROLE_booking-reader");
    }
}
