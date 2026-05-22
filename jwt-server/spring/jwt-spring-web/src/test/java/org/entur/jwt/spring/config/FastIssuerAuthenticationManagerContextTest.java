package org.entur.jwt.spring.config;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.junit5.claim.Issuer;
import org.entur.jwt.junit5.sabotage.Signature;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.entur.jwt.spring.rest.Greeting;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Spring context test verifying that {@link FastIssuerAuthenticationManager} is wired
 * with a shared {@link JwtHeaderToIssuerMapper} bean when multi-tenant and
 * {@code entur.jwt.decode.header.map-to-issuer.enabled=true}.
 */
@AuthorizationServer("a")
@AuthorizationServer("b")
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@TestPropertySource(properties = {"entur.jwt.decode.header.map-to-issuer.enabled=true"})
public class FastIssuerAuthenticationManagerContextTest {

    @LocalServerPort
    private int randomServerPort;

    @Autowired
    private TestRestTemplate restTemplate;

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

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        String url = "http://localhost:" + randomServerPort + "/protected";
        ResponseEntity<Greeting> response = restTemplate.exchange(url, HttpMethod.GET, entity, Greeting.class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();

        // After the first request the slow path runs, extracting the issuer from the JWT
        // and caching the raw header segment → issuer mapping.
        String rawToken = token.substring("Bearer ".length());
        assertThat(jwtHeaderToIssuerMapper.get(rawToken)).isNotNull();
        assertThat(jwtHeaderToIssuerMapper.getHeaderToIssuer()).hasSize(1);
    }

    @Test
    public void testMapperNotGrownAfterSecondRequestWithSameHeader(
            @AccessToken(by = "a", audience = "mock.my.audience") String token) {

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        String url = "http://localhost:" + randomServerPort + "/protected";

        // First request: slow path, populates the mapper
        restTemplate.exchange(url, HttpMethod.GET, entity, Greeting.class);
        assertThat(jwtHeaderToIssuerMapper.getHeaderToIssuer()).hasSize(1);

        // Second request with the same token: fast path, mapper size stays the same
        restTemplate.exchange(url, HttpMethod.GET, entity, Greeting.class);
        assertThat(jwtHeaderToIssuerMapper.getHeaderToIssuer()).hasSize(1);
    }

    @Test
    public void testInvalidTokenHeaderNotCachedForMalformedToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer not.a.valid.jwt");
        HttpEntity<String> entity = new HttpEntity<>(headers);

        String url = "http://localhost:" + randomServerPort + "/protected";
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        // Malformed tokens must not be added to the cache
        assertThat(jwtHeaderToIssuerMapper.getHeaderToIssuer()).isEmpty();
    }

    @Test
    public void testInvalidTokenHeaderNotCachedForInvalidSignature(
            @AccessToken(by = "a", audience = "mock.my.audience") @Signature("tampered") String token) {

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        String url = "http://localhost:" + randomServerPort + "/protected";
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        // Tokens that fail signature verification must not be added to the cache
        assertThat(jwtHeaderToIssuerMapper.getHeaderToIssuer()).isEmpty();
    }

    @Test
    public void testInvalidTokenHeaderNotCachedForUnknownIssuer(
            @AccessToken(by = "a", audience = "mock.my.audience") @Issuer("https://unknown.issuer") String token) {

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        String url = "http://localhost:" + randomServerPort + "/protected";
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        // Tokens with an unrecognised issuer must not be added to the cache
        assertThat(jwtHeaderToIssuerMapper.getHeaderToIssuer()).isEmpty();
    }
}
