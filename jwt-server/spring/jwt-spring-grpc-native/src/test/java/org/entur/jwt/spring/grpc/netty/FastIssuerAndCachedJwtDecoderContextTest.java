package org.entur.jwt.spring.grpc.netty;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import org.entur.jwt.junit5.AccessToken;
import org.entur.jwt.junit5.AuthorizationServer;
import org.entur.jwt.spring.JwkSourceMap;
import org.entur.jwt.spring.cache.DecodedJwtCacheJwtDecoder;
import org.entur.jwt.spring.decode.FastIssuerJwtDecoder;
import org.entur.jwt.spring.grpc.AbstractGrpcTest;
import org.entur.jwt.spring.grpc.test.GreetingResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Verify JWT caching with header-to-issuer mapping enabled.
 */
@AuthorizationServer("a")
@AuthorizationServer("b")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "entur.jwt.decode.header.map-to-issuer.enabled=true",
        "entur.jwt.tenants.a.decoder-cache.enabled=true",
        "entur.jwt.jwk.cache.preemptive.eager.enabled=true",
})
@DirtiesContext
public class FastIssuerAndCachedJwtDecoderContextTest extends AbstractGrpcTest {

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private JwkSourceMap jwkSourceMap;

    @BeforeEach
    public void readniess() throws Exception {
        // make sure JWKs are loaded. trigger JWKs population
        Map<String, JWKSource> jwkSources = jwkSourceMap.getJwkSources();
        for (Map.Entry<String, JWKSource> entry : jwkSources.entrySet()) {

            JWKSelector mock = mock(JWKSelector.class);
            when(mock.select(any())).thenReturn(List.of(mock(JWK.class)));
            entry.getValue().get(mock, null);
        }
    }

    @Test
    public void testContextLoadsWithMapperBean() {
        assertThat(jwtDecoder).isInstanceOf(FastIssuerJwtDecoder.class);

        FastIssuerJwtDecoder fastIssuerJwtDecoder = (FastIssuerJwtDecoder) jwtDecoder;
        assertEquals(2, fastIssuerJwtDecoder.getJwtDecoders().size());

        JwtDecoder a = fastIssuerJwtDecoder.getJwtDecoders().get("https://mock.issuer.a.xyz");
        assertThat(a).isInstanceOf(DecodedJwtCacheJwtDecoder.class);

        JwtDecoder b = fastIssuerJwtDecoder.getJwtDecoders().get("https://mock.issuer.b.xyz");
        assertThat(b).isInstanceOf(NimbusJwtDecoder.class);
    }

    @Test
    public void testCachePopulatedAfterAuthenticatedRequests(
            @AccessToken(by = "a", audience = "https://my.audience", scope =  "1") String token1,
            @AccessToken(by = "a", audience = "https://my.audience", scope =  "2") String token2
    ) {
        FastIssuerJwtDecoder fastIssuerJwtDecoder = (FastIssuerJwtDecoder) jwtDecoder;
        DecodedJwtCacheJwtDecoder a = (DecodedJwtCacheJwtDecoder)fastIssuerJwtDecoder.getJwtDecoders().get("https://mock.issuer.a.xyz");
        a.clear();

        GreetingResponse response1 = stub(token1).protectedWithPartnerTenant(greetingRequest);
        assertEquals(1, a.getSize());

        GreetingResponse response2 = stub(token2).protectedWithPartnerTenant(greetingRequest);
        assertEquals(2, a.getSize());
    }

    @Test
    public void testCacheNotGrownAfterSecondRequestWithSameJwt(@AccessToken(by = "a", audience = "https://my.audience") String token) {
        FastIssuerJwtDecoder fastIssuerJwtDecoder = (FastIssuerJwtDecoder) jwtDecoder;
        DecodedJwtCacheJwtDecoder a = (DecodedJwtCacheJwtDecoder)fastIssuerJwtDecoder.getJwtDecoders().get("https://mock.issuer.a.xyz");
        a.clear();

        GreetingResponse response1 = stub(token).protectedWithPartnerTenant(greetingRequest);
        assertEquals(1, a.getSize());

        GreetingResponse response2 = stub(token).protectedWithPartnerTenant(greetingRequest);
        assertEquals(1, a.getSize());
    }

}
