package org.entur.jwt.spring.grpc.netty;

import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.decode.JwtHeaderToIssuerMapper;
import org.entur.jwt.spring.grpc.AbstractGrpcTest;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Spring context test verifying that {@link FastIssuerJwtDecoder} is wired with a shared
 * {@link JwtHeaderToIssuerMapper} bean when multi-tenant and
 * {@code entur.jwt.decode.header.map-to-issuer.enabled=true}.
 */
@AuthorizationServer("a")
@AuthorizationServer("b")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {"entur.jwt.decode.header.map-to-issuer.enabled=true"})
@DirtiesContext
public class FastIssuerJwtDecoderContextTest extends AbstractGrpcTest {

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
            @AccessToken(by = "a", audience = "https://my.audience") String token) {

        GreetingResponse response = stub(token).protectedWithPartnerTenant(greetingRequest);
        assertThat(response.getMessage()).isEqualTo("Hello protected tenant");

        // After the first request the slow path runs, extracting the issuer from the JWT
        // and caching the raw header segment → issuer mapping.
        String rawToken = token.substring("Bearer ".length());
        assertThat(jwtHeaderToIssuerMapper.get(rawToken)).isNotNull();
        assertThat(jwtHeaderToIssuerMapper.getHeaderToIssuer()).hasSize(1);
    }

    @Test
    public void testMapperNotGrownAfterSecondRequestWithSameHeader(
            @AccessToken(by = "a", audience = "https://my.audience") String token) {

        // First request: slow path, populates the mapper
        stub(token).protectedWithPartnerTenant(greetingRequest);
        assertThat(jwtHeaderToIssuerMapper.getHeaderToIssuer()).hasSize(1);

        // Second request with the same token: fast path, mapper size stays the same
        stub(token).protectedWithPartnerTenant(greetingRequest);
        assertThat(jwtHeaderToIssuerMapper.getHeaderToIssuer()).hasSize(1);
    }
}
