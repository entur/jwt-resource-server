package org.entur.jwt.spring.config;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * Verify header-to-issuer mapping for tenants whose tokens have identical headers,
 * i.e. which share a signing key and key id.
 */
@AuthorizationServer(value = "a", encoder = SharedKeyAuthorizationServerEncoder.class)
@AuthorizationServer(value = "b", encoder = SharedKeyAuthorizationServerEncoder.class)
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@TestPropertySource(properties = {"entur.jwt.decode.header.map-to-issuer.enabled=true"})
public class FastReactiveIssuerSharedHeaderAuthenticationManagerContextTest {

    @Autowired
    private WebTestClient webTestClient;

    @Autowired
    private JwtHeaderToIssuerMapper jwtHeaderToIssuerMapper;

    @BeforeEach
    public void clearMapper() {
        jwtHeaderToIssuerMapper.clear();
    }

    @Test
    public void testAuthenticatesTokensOfBothTenants(
            @AccessToken(by = "a", audience = "mock.my.audience") String tokenA,
            @AccessToken(by = "b", audience = "mock.my.audience") String tokenB) {
        assertAuthenticatesBoth(tokenA, tokenB);
    }

    @Test
    public void testAuthenticatesTokensOfBothTenantsInReverseOrder(
            @AccessToken(by = "a", audience = "mock.my.audience") String tokenA,
            @AccessToken(by = "b", audience = "mock.my.audience") String tokenB) {
        assertAuthenticatesBoth(tokenB, tokenA);
    }

    @Test
    public void testRejectsExpiredTokenOfOtherTenant(
            @AccessToken(by = "a", audience = "mock.my.audience") String tokenA,
            @AccessToken(by = "b", audience = "mock.my.audience", expiresAt = -600) String expiredTokenB) {
        assertThat(request(tokenA)).isEqualTo(HttpStatus.OK);

        assertThat(request(expiredTokenB)).isEqualTo(HttpStatus.UNAUTHORIZED);

        // not authenticated for the other tenant, so still mapped
        assertThat(jwtHeaderToIssuerMapper.get(rawToken(tokenA))).isEqualTo("https://mock.issuer.a.xyz");
    }

    private void assertAuthenticatesBoth(String first, String second) {
        assertThat(header(first)).isEqualTo(header(second));

        assertThat(request(first)).isEqualTo(HttpStatus.OK);
        assertThat(jwtHeaderToIssuerMapper.get(rawToken(first))).isNotNull();

        assertThat(request(second)).isEqualTo(HttpStatus.OK);
        // the header no longer identifies the tenant
        assertThat(jwtHeaderToIssuerMapper.get(rawToken(first))).isNull();
        assertThat(jwtHeaderToIssuerMapper.getSharedHeaders()).containsExactly(header(first));

        assertThat(request(first)).isEqualTo(HttpStatus.OK);
        assertThat(request(second)).isEqualTo(HttpStatus.OK);
    }

    private HttpStatus request(String token) {
        return HttpStatus.valueOf(webTestClient
                .get()
                .uri("/protected")
                .header(AUTHORIZATION, token)
                .exchange()
                .returnResult(String.class)
                .getStatus()
                .value());
    }

    private static String rawToken(String token) {
        return token.substring("Bearer ".length());
    }

    private static String header(String token) {
        String raw = rawToken(token);
        return raw.substring(0, raw.indexOf('.'));
    }
}
