package org.entur.jwt.spring.config;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.actuate.AbstractActuatorTest;
import org.entur.jwt.spring.decode.cache.DecodedJwtCacheJwtDecoder;
import org.entur.jwt.spring.decode.ClosableJwtDecoders;
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
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verify JWT caching with header-to-issuer mapping enabled.
 */

@AuthorizationServer("a")
@AuthorizationServer("b")
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@TestPropertySource(properties = {
        "entur.jwt.decode.header.map-to-issuer.enabled=true",
        "entur.jwt.tenants.a.decoder-cache.enabled=true",
        "entur.jwt.jwk.cache.preemptive.eager.enabled=true",
})
public class FastIssuerAndCachedJwtsAuthenticationManagerContextTest extends AbstractActuatorTest {

    @LocalServerPort
    private int randomServerPort;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private ClosableJwtDecoders closableJwtDecoders;

    @BeforeEach
    public void readinessProbe() throws Exception {
        // make sure JWKs are loaded.

        HttpHeaders headers = new HttpHeaders();
        HttpEntity<String> entity = new HttpEntity<String>(headers);

        String url = "http://localhost:" + randomServerPort + "/actuator/health/readiness";

        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);

        if(!response.getStatusCode().is2xxSuccessful()) {
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
            waitForHealth();

            response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);
            assertTrue(response.getStatusCode().is2xxSuccessful());
        }
    }

    @Test
    public void testBeans() {
        assertEquals(2, closableJwtDecoders.getJwtDecoders().size());

        JwtDecoder a = closableJwtDecoders.getJwtDecoders().get("https://mock.issuer.a.xyz");
        assertThat(a).isInstanceOf(DecodedJwtCacheJwtDecoder.class);

        JwtDecoder b = closableJwtDecoders.getJwtDecoders().get("https://mock.issuer.b.xyz");
        assertThat(b).isInstanceOf(NimbusJwtDecoder.class);
    }

    @Test
    public void testCachePopulatedAfterAuthenticatedRequests(
            @AccessToken(by = "a", audience = "mock.my.audience", scope =  "1") String token1, @AccessToken(by = "a", audience = "mock.my.audience", scope =  "2") String token2) {

        DecodedJwtCacheJwtDecoder a = (DecodedJwtCacheJwtDecoder) closableJwtDecoders.getJwtDecoders().get("https://mock.issuer.a.xyz");
        a.clear();

        assertRequest(token1);
        assertEquals(1, a.getSize());

        assertRequest(token2);
        assertEquals(2, a.getSize());
    }

    @Test
    public void testCacheNotGrownAfterSecondRequestWithSameJwt(
            @AccessToken(by = "a", audience = "mock.my.audience") String token) {

        DecodedJwtCacheJwtDecoder a = (DecodedJwtCacheJwtDecoder) closableJwtDecoders.getJwtDecoders().get("https://mock.issuer.a.xyz");
        a.clear();

        assertRequest(token);
        assertEquals(1, a.getSize());

        assertRequest(token);
        assertEquals(1, a.getSize());
    }

    private void assertRequest(String token1) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", token1);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        String url = "http://localhost:" + randomServerPort + "/protected";
        ResponseEntity<Greeting> response = restTemplate.exchange(url, HttpMethod.GET, entity, Greeting.class);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
    }
}
