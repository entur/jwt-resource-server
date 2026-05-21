package org.entur.jwt.spring.config;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.entur.jwt.spring.rest.Greeting;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * Spring context test verifying that {@link FastReactiveIssuerAuthenticationManager} is wired
 * with a shared {@link JwtHeaderToIssuerMapper} bean when multi-tenant and
 * {@code entur.jwt.decode.header.map-to-issuer.enabled=true}.
 */
@AuthorizationServer("a")
@AuthorizationServer("b")
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@TestPropertySource(properties = {"entur.jwt.decode.header.map-to-issuer.enabled=true"})
public class FastReactiveIssuerAuthenticationManagerContextTest {

    @Autowired
    private WebTestClient webTestClient;

    @Autowired
    private JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper;

    @BeforeEach
    public void clearMapper() {
        jwtHeaderToIssuerMapper.clear();
    }

    @Test
    public void testContextLoadsWithMapperBean() {
        assertThat(jwtHeaderToIssuerMapper).isNotNull();
        assertThat(jwtHeaderToIssuerMapper.getHeaderToIssuer()).isEmpty();
    }

    @Test
    public void testMapperPopulatedAfterAuthenticatedRequest(
            @AccessToken(by = "a", audience = "mock.my.audience") String token) {

        webTestClient
                .get()
                .uri("/protected")
                .header(AUTHORIZATION, token)
                .exchange()
                .expectStatus().is2xxSuccessful()
                .returnResult(Greeting.class)
                .getResponseBody().blockLast();

        // After the first request the slow path runs, extracting the issuer from the JWT
        // and caching the raw header segment → issuer mapping.
        String rawToken = token.substring("Bearer ".length());
        assertThat(jwtHeaderToIssuerMapper.get(rawToken)).isNotNull();
        assertThat(jwtHeaderToIssuerMapper.getHeaderToIssuer()).hasSize(1);
    }

    @Test
    public void testMapperNotGrownAfterSecondRequestWithSameHeader(
            @AccessToken(by = "a", audience = "mock.my.audience") String token) {

        // First request: slow path, populates the mapper
        webTestClient
                .get()
                .uri("/protected")
                .header(AUTHORIZATION, token)
                .exchange()
                .expectStatus().is2xxSuccessful()
                .returnResult(Greeting.class)
                .getResponseBody().blockLast();

        assertThat(jwtHeaderToIssuerMapper.getHeaderToIssuer()).hasSize(1);

        // Second request with the same token: fast path, mapper size stays the same
        webTestClient
                .get()
                .uri("/protected")
                .header(AUTHORIZATION, token)
                .exchange()
                .expectStatus().is2xxSuccessful()
                .returnResult(Greeting.class)
                .getResponseBody().blockLast();

        assertThat(jwtHeaderToIssuerMapper.getHeaderToIssuer()).hasSize(1);
    }
}
